# Log a webhook payload that failed to parse

A webhook handler or a queue consumer receives JSON from outside, and some of it does not parse: a
sender cut the body short, a proxy answered with an HTML page, a field changed its type. The log
line that explains the failure needs the payload, and the payload holds emails, phone numbers and
amounts that a log must not keep. `RedactedJson` writes an outline of the bytes instead: the shape
of the JSON, with every value hidden unless the application opts into showing it. It does no
encryption and needs no KMS, so it works for any bytes and any logger. It needs no Cargo feature.

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
`Io`.

## Choose what the outline shows

A policy is a type of the application's own that implements `JsonRedaction` and sets the constants
it needs, each of them off by default: `FIELD_NAMES` shows the keys, `SIZES` the lengths, and
`REVEALED_FIELDS` the values of the fields it lists, such as `items[].sku` for the `sku` of every item
of `items`. Every constant and the grammar of a path are in
[Redaction policies](../stored-values.md#redaction-policies).

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

## Input that is not JSON

Broken, truncated and non-JSON input is outlined as far as it goes, and the outline never panics.
An HTML error page from a proxy and a base64 string print as their class only, and a syntax error in
the middle ends the outline there, with serde_json's fixed message:

```text
not JSON: text
not JSON: base64-like text
{"event": "order.paid", "a": <error: expected value>
```

## What to watch for

- Log the category from `error.classify()`, and not the message of `serde_json::Error`, which for a
  value of the wrong type can quote the input;
- revealed values go to the log whenever the JSON fails to parse. Reveal codes and identifiers, never
  personal data;
- `SIZES` has a cost: a length gives away a hidden boolean, since `true` and `false` differ in
  length, and it narrows a short string down. Leave it off for any payload where that matters;
- an outline is bounded in length and depth, see the limits in
  [Redaction policies](../stored-values.md#redaction-policies).

`JsonEncoded<T, P>` applies the same policies to the JSON that fails to decode after an encrypted
value is opened, see [JSON that does not decode](../stored-values.md#json-that-does-not-decode). The
event it logs is in [Spans and events](../observability/spans-and-events.md#json-that-does-not-decode).
