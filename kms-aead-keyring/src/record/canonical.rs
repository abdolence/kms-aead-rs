//! The canonical form of a record's JSON document, which its signature covers: the JSON
//! Canonicalization Scheme of RFC 8785 over the parsed document, so that every store's copy
//! canonicalises to the same bytes whatever its member order or whitespace.

use serde_json::Value;

/// The largest integer an IEEE 754 double holds exactly, the range in which RFC 8785 writes an
/// integer as its decimal digits.
const MAX_EXACT_INTEGER: u64 = 1 << 53;

/// Why a document has no canonical form here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalError {
    /// A number RFC 8785 writes in ECMAScript's shortest form, which this release does not: a
    /// fraction, an exponent, or an integer beyond 2^53. A record writes none.
    UnsupportedNumber,
    /// serde_json refused to write a string.
    Unwritable,
}

/// `value` canonicalised as RFC 8785 does: object members sorted by the UTF-16 code units of
/// their names, no whitespace, strings escaped as serde_json escapes them, which is RFC 8785's
/// escaping, and integers in decimal.
pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_canonical_value(value, &mut out)?;
    Ok(out)
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let exact = number
                .as_u64()
                .filter(|integer| *integer <= MAX_EXACT_INTEGER)
                .map(|integer| integer.to_string())
                .or_else(|| {
                    number
                        .as_i64()
                        .filter(|integer| integer.unsigned_abs() <= MAX_EXACT_INTEGER)
                        .map(|integer| integer.to_string())
                })
                .ok_or(CanonicalError::UnsupportedNumber)?;
            out.extend_from_slice(exact.as_bytes());
        }
        Value::String(string) => write_canonical_string(string, out)?,
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            // serde_json's map is ordered by UTF-8 bytes, or by insertion where another crate in
            // the build turns on its `preserve_order`; RFC 8785 orders by UTF-16 code units.
            let mut members = members.iter().collect::<Vec<_>>();
            members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            out.push(b'{');
            for (index, (name, member)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_string(name, out)?;
                out.push(b':');
                write_canonical_value(member, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// serde_json escapes `"`, `\` and the control characters, with `\b`, `\t`, `\n`, `\f` and `\r`
/// where they exist and `\u00xx` in lowercase hex otherwise, and writes every other character as
/// its UTF-8: RFC 8785's rules for strings.
fn write_canonical_string(string: &str, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    serde_json::to_writer(&mut *out, string).map_err(|_| CanonicalError::Unwritable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_are_sorted_and_strings_escaped_as_rfc_8785_does() {
        let document: Value = serde_json::from_str(
            r#"{ "b": [true, null, -3], "a": "\u0007 é \" \\ / \u007f", "｡": 1, "😀": 2, "z": {} }"#,
        )
        .unwrap();

        let canonical = canonical_json(&document).unwrap();

        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            "{\"a\":\"\\u0007 é \\\" \\\\ / \u{7f}\",\"b\":[true,null,-3],\"z\":{},\"😀\":2,\"｡\":1}"
        );
    }

    #[test]
    fn a_number_rfc_8785_writes_otherwise_is_refused() {
        for refused in ["1.5", "1e3", "9007199254740993"] {
            let document: Value = serde_json::from_str(refused).unwrap();
            assert_eq!(
                canonical_json(&document),
                Err(CanonicalError::UnsupportedNumber),
                "{refused}"
            );
        }
    }
}
