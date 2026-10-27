# Log JSON payloads without leaking data

A webhook handler or a queue consumer receives JSON from outside, and some of it does not parse: a
sender cut the body short, a proxy answered with an HTML page, a field changed its type. The log
line that explains the failure needs the payload, and the payload holds emails, phone numbers and
amounts that a log must not keep. `RedactedJson` writes an outline of the bytes instead: the shape
of the JSON, with every value hidden unless the application opts into showing it. It does no
encryption and needs no KMS, so it works for any bytes and any logger. `kms-aead` builds without
features for it, which is the default.

## Outline instead of the payload

`RedactedJson::new::<P>(bytes)` takes the bytes and a policy `P`, a type that says what the outline
shows. `ShapeOnly` shows nothing but the shape. `Display` and `Debug` both write the outline and never
the bytes, so the value goes to `format!`, to `tracing` as a field, to `log` or to a logger of the
application's own.

```rust
use kms_aead::redaction::{RedactedJson, ShapeOnly};

fn reject(body: &[u8]) {
    if let Err(error) = serde_json::from_slice::<serde_json::Value>(body) {
        eprintln!(
            "WARN webhook payload rejected ({:?}): {}",
            error.classify(),
            RedactedJson::new::<ShapeOnly>(body)
        );
    }
}
# let body = br#"{"event":"order.paid","customer":{"email":"ann@example.com"},"paid":true,"total_cents":117"#;
# reject(body);
# assert_eq!(
#     RedactedJson::new::<ShapeOnly>(body).to_string(),
#     "{<key>: <string>, <key>: {<key>: <string>}, <key>: <bool>, <key>: <number>, <error: EOF while parsing an object>"
# );
```

A body that stops inside `total_cents` logs this line:

```text
WARN webhook payload rejected (Eof): {<key>: <string>, <key>: {<key>: <string>}, <key>: <bool>, <key>: <number>, <error: EOF while parsing an object>
```

The log shows the type of every value, `<key>` for every key, the nesting, and where serde_json
stopped reading. `error.classify()` gives the category of the failure, `Eof`, `Syntax`, `Data` or
`Io`. Log that, and not the message of `serde_json::Error`, which for a value of the wrong type can
quote the input.

## Choose what the outline shows

A policy is a type of the application's own that implements `JsonRedaction` and sets the constants
it needs. Each constant is off by default:

| Constant | Effect on the outline |
|---|---|
| `FIELD_NAMES` | shows the keys of objects, except the keys of `DATA_KEYED_MAPS`; |
| `DATA_KEYED_MAPS` | lists the objects whose keys are data, such as a map from an email to a balance, so their keys stay hidden; `balances[]` names the values of the map `balances`; |
| `SIZES` | shows the length of every hidden value and key, the length of the JSON and the line and column of the failure; |
| `REVEALED_FIELDS` | shows the values of the listed fields, and the names of the fields on the way to each. |

```rust
use kms_aead::redaction::{FieldPaths, JsonRedaction, RedactedJson};

struct WebhookLog;

impl JsonRedaction for WebhookLog {
    const FIELD_NAMES: bool = true;
    const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["event", "items[].sku"]);
}
# let body = br#"{"event":"order.paid","customer":{"email":"ann@example.com"},"items":[{"sku":"desk","qty":2},{"sku":"lamp","qty":1}],"total_cents":117"#;
let outline = RedactedJson::new::<WebhookLog>(body);
# assert_eq!(
#     outline.to_string(),
#     r#"{"event": "order.paid", "customer": {"email": <string>}, "items": [{"sku": "desk", "qty": <number>}, {"sku": "lamp", "qty": <number>}], "total_cents": <number>, <error: EOF while parsing an object>"#
# );
```

The outline of the same kind of body:

```text
{"event": "order.paid", "customer": {"email": <string>}, "items": [{"sku": "desk", "qty": <number>}, {"sku": "lamp", "qty": <number>}], "total_cents": <number>, <error: EOF while parsing an object>
```

A path is the names of the fields joined by `.`, with `[]` after a field for every item of the array
it holds, such as `customer.plan` or `items[].sku`, and `[].id` for the items of an array at the top
level. A path takes in the whole value at its end. A field whose name has a `.`, `[` or `]` cannot
be named. A malformed path is a compile error in the build that uses the policy.

Revealed values go to the log whenever the JSON fails to parse. Reveal codes and identifiers, never
personal data.

`SIZES` has a cost: a length gives away a hidden boolean, since `true` and `false` differ in
length, and it narrows a short string down. Leave it off for any payload where that matters.

## Input that is not JSON

Broken, truncated and non-JSON input is outlined as far as it goes, and the outline never panics.
An HTML error page from a proxy and a base64 string print as their class only, and a syntax error in
the middle ends the outline there, with serde_json's fixed message:

```text
not JSON: text
not JSON: base64-like text
{"event": "order.paid", "a": <error: expected value>
```

The classes of bytes that do not start as JSON are `empty`, `whitespace only`, `hex digits`,
`base64-like text`, `text` and `binary data`.

## Limits

- The outline is one line of printable ASCII, 4 KiB at most, whatever the input;
- a revealed string is escaped, with `"`, `\`, `<`, `>` and every character outside printable ASCII
  written as JSON escapes, and cut after 64 bytes;
- the items of an array with the shape of the item before them print as a count, such as `<2 more
  of the same shape>`, and an array prints 8 items of different shapes at most;
- serde_json reads 128 levels of nesting at most.

`JsonEncoded<T, P>` applies the same policies to the JSON that fails to decode after an encrypted
value is opened, see [JSON that does not decode](../stored-values.md#json-that-does-not-decode). The
event it logs is in [Observability](../observability.md#json-that-does-not-decode).
