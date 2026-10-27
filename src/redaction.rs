//! What the `WARN` event of a [`JsonEncoded`](crate::JsonEncoded) value that does not decode shows
//! of its JSON: a [`RedactedJson`] outline under the type's [`JsonRedaction`] policy, which an
//! application can also log for JSON of its own.

use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;

use crate::errors::json_error_category;

/// What the outline of JSON that does not decode shows besides its shape: the policy `P` of a
/// [`JsonEncoded<T, P>`](crate::JsonEncoded), a type of the application's own whose constants opt
/// into each disclosure. [`ShapeOnly`], the default, opts into none.
///
/// A plaintext is encrypted because it is secret, so its outline stays [`ShapeOnly`] or reveals
/// codes and identifiers only. A signed payload is often not secret, and its outline may show more.
///
/// Under every policy the outline ends with serde_json's message for a syntax error, such as
/// `EOF while parsing a string`. It is fixed text that never quotes the input, and it can state a
/// property of a value the outline hides: `number out of range`, `control character
/// (\u0000-\u001F) found while parsing a string`, `invalid unicode code point` or `unexpected end
/// of hex escape`. Any other error shows its category only, such as `Data error`.
///
/// ```rust
/// use kms_aead::redaction::{FieldPaths, JsonRedaction};
/// use kms_aead::JsonEncoded;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Invoice {
///     number: String,
///     customer: String,
/// }
///
/// struct InvoiceLog;
///
/// impl JsonRedaction for InvoiceLog {
///     const SIZES: bool = true;
///     const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["number"]);
/// }
///
/// type InvoiceJson = JsonEncoded<Invoice, InvoiceLog>;
///
/// let invoice = InvoiceJson::from(Invoice {
///     number: "INV-1042".to_string(),
///     customer: "Northwind Traders".to_string(),
/// });
/// ```
pub trait JsonRedaction {
    /// Whether the outline shows field names, the keys of objects, except the keys of
    /// [`DATA_KEYED_MAPS`](Self::DATA_KEYED_MAPS).
    const FIELD_NAMES: bool = false;

    /// The objects whose keys are data rather than field names, such as a map from a customer's
    /// email to a balance: their keys stay hidden under [`FIELD_NAMES`](Self::FIELD_NAMES). A `[]`
    /// after the path of such an object names its values, whatever their keys: `balances[].total`
    /// can be revealed, and `balances[]` listed here when the values are maps keyed by data too.
    const DATA_KEYED_MAPS: FieldPaths = FieldPaths::NONE;

    /// Whether the outline shows sizes: the length of every value and key it hides, the length of
    /// the JSON in bytes, and the line and column where serde_json stopped reading it. A length
    /// gives away a hidden boolean, `true` against `false`, and narrows a short value down.
    const SIZES: bool = false;

    /// The fields whose values the outline shows, and with them the names of the fields on the
    /// way to each.
    const REVEALED_FIELDS: FieldPaths = FieldPaths::NONE;
}

/// The default [`JsonRedaction`]: the outline shows the shape of the JSON only, and serde_json's
/// message for a syntax error, which can state a property of a hidden value, see
/// [`JsonRedaction`].
pub struct ShapeOnly;

impl JsonRedaction for ShapeOnly {}

/// Fields of a JSON document, as paths: field names joined by `.`, and `[]` after a field for
/// every item of the array it holds, or every value of the data-keyed map it holds, such as
/// `number`, `lines[].quantity`, or `[].id` for the items of an array at the top level. A path
/// takes in the whole value at its end. A field whose name holds `.`, `[` or `]` cannot be named.
#[derive(Debug, Clone, Copy)]
pub struct FieldPaths(&'static [&'static str]);

impl FieldPaths {
    /// No field.
    pub const NONE: Self = Self(&[]);

    /// The fields at `paths`.
    ///
    /// # Panics
    ///
    /// When a path is empty, has an empty field name, a `[` not followed by `]`, a `]` alone, or a
    /// field name right after `[]`. In a `const` item that is a compile error of every build. In a
    /// [`JsonRedaction`] constant it is a compile error of the build that decodes with the policy,
    /// which `cargo check` does not report.
    pub const fn from_static(paths: &'static [&'static str]) -> Self {
        let mut index = 0;
        while index < paths.len() {
            if !Self::is_field_path(paths[index].as_bytes()) {
                panic!("a field path is field names joined by `.`, with `[]` after a field for the items of its array");
            }
            index += 1;
        }
        Self(paths)
    }

    /// Whether `path` is field names joined by `.`, each followed by any number of `[]`, the first
    /// of which may be `[]` alone.
    const fn is_field_path(path: &[u8]) -> bool {
        let mut index = 0;
        let mut first = true;
        loop {
            let start = index;
            while index < path.len() && !matches!(path[index], b'.' | b'[' | b']') {
                index += 1;
            }
            let named = index > start;
            let mut items = false;
            while index + 1 < path.len() && path[index] == b'[' && path[index + 1] == b']' {
                index += 2;
                items = true;
            }
            if !named && !(first && items) {
                return false;
            }
            if index == path.len() {
                return true;
            }
            if path[index] != b'.' {
                return false;
            }
            index += 1;
            first = false;
        }
    }
}

/// An outline of JSON bytes that may be broken, for a log line: its shape, and what its
/// [`JsonRedaction`] policy opts into. `Display` writes the outline, and so does `Debug`, never the
/// bytes.
///
/// The outline is one line of printable ASCII, 4 KiB at most:
///
/// - a value prints as its type, `<string>`, `<number>` or `<bool>`, a key as `<key>`, and `null`
///   as itself. With [`SIZES`](JsonRedaction::SIZES), a string, number or key prints its length
///   too, such as `<string, 17 chars>`, and the outline starts with the length of the JSON;
/// - a key prints itself under [`FIELD_NAMES`](JsonRedaction::FIELD_NAMES), and on the way to a
///   revealed field;
/// - a revealed value prints itself, a string escaped and cut after 64 bytes: `"`, `\`, `<`, `>`
///   and every character outside printable ASCII as a JSON escape;
/// - the items of an array with the shape of the item before them print as a count, such as
///   `<2 more of the same shape>`, and an array prints 8 items of different shapes at most;
/// - where serde_json stops reading the JSON, the outline ends with its error, such as
///   `<error: EOF while parsing a string>`, with the line and column under `SIZES`. serde_json
///   reads 128 levels of nesting at most;
/// - bytes that do not start as JSON print as their class only, such as `base64-like text`.
///
/// The outline is built when it is formatted, in time linear in the input, and never panics.
/// With serde_json's `arbitrary_precision` feature on, a number prints as an object of one
/// string.
///
/// ```rust
/// use kms_aead::redaction::{FieldPaths, JsonRedaction, RedactedJson};
///
/// struct OrderLog;
///
/// impl JsonRedaction for OrderLog {
///     const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["id", "lines[].sku"]);
/// }
///
/// let body = br#"{"id":"A-17","email":"ann@example.com","lines":[{"sku":"desk","price":"#;
/// let outline = RedactedJson::new::<OrderLog>(body);
///
/// tracing::warn!(%outline, "An order that does not parse");
/// assert_eq!(
///     outline.to_string(),
///     r#"{"id": "A-17", <key>: <string>, "lines": [{"sku": "desk", <key>: <error: EOF while parsing a value>"#
/// );
/// ```
pub struct RedactedJson<'a> {
    json: &'a [u8],
    policy: Policy,
}

impl<'a> RedactedJson<'a> {
    /// The outline of `json` under the policy `P`.
    pub fn new<P: JsonRedaction>(json: &'a [u8]) -> Self {
        Self {
            json,
            policy: Policy {
                field_names: P::FIELD_NAMES,
                data_keyed_maps: P::DATA_KEYED_MAPS,
                sizes: P::SIZES,
                revealed_fields: P::REVEALED_FIELDS,
            },
        }
    }

    /// serde_json's `error` as far as the policy shows it, for the event beside the outline.
    pub(crate) fn describe(&self, error: &serde_json::Error) -> String {
        self.policy.describe(error)
    }
}

impl Display for RedactedJson<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&Outliner::new(self.policy).outline(self.json))
    }
}

/// The outline, as `Display` writes it.
impl Debug for RedactedJson<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/// The constants of a [`JsonRedaction`].
#[derive(Clone, Copy)]
struct Policy {
    field_names: bool,
    data_keyed_maps: FieldPaths,
    sizes: bool,
    revealed_fields: FieldPaths,
}

impl Policy {
    /// serde_json's `error` as far as the policy shows it: the message of a syntax error, which is
    /// fixed text, or the category of any other, and the position under `SIZES`.
    fn describe(&self, error: &serde_json::Error) -> String {
        let position = format!(" at line {} column {}", error.line(), error.column());
        let message = error.to_string();
        let mut description = Self::fixed_message(error.classify(), &message, &position);
        if self.sizes && error.line() > 0 {
            description.push_str(&position);
        }
        description
    }

    /// The `message` of an error of `category` without its `position`, when serde_json writes the
    /// message from fixed text that never quotes the input, as it does for a syntax error. The
    /// message of a data error may quote the input, so any other category, and a message that does
    /// not end with `position`, give the category alone.
    fn fixed_message(category: Category, message: &str, position: &str) -> String {
        match category {
            Category::Syntax | Category::Eof => message
                .strip_suffix(position)
                .map_or_else(|| json_error_category(category), ToString::to_string),
            category => json_error_category(category),
        }
    }
}

/// The longest outline, in bytes.
const MAX_OUTLINE_LEN: usize = 4096;
/// The bytes of [`MAX_OUTLINE_LEN`] kept for the annotations at the end of an outline.
const OUTLINE_END_RESERVE: usize = 256;
/// The items of different shapes an array shows.
const MAX_ITEMS_SHOWN: usize = 8;
/// The longest revealed string, escaped, in bytes.
const MAX_REVEALED_LEN: usize = 64;

/// The fields the policy names, as a tree of their steps that an outline walks beside the JSON.
struct FieldTree(Vec<FieldNode>);

#[derive(Default)]
struct FieldNode {
    children: Vec<(Step<'static>, usize)>,
    revealed: bool,
    toward_revealed: bool,
    data_keyed_map: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Step<'a> {
    Field(&'a str),
    Items,
}

/// Where a value is in the [`FieldTree`].
#[derive(Clone, Copy)]
enum Position {
    /// At or below a revealed field.
    Revealed,
    Node(usize),
    /// Below no field the policy names.
    Outside,
}

impl FieldTree {
    fn new(policy: Policy) -> Self {
        let mut tree = Self(vec![FieldNode::default()]);
        for (paths, revealed) in [
            (policy.revealed_fields, true),
            (policy.data_keyed_maps, false),
        ] {
            for path in paths.0 {
                let mut node = 0;
                for step in path.split('.').flat_map(|segment| {
                    let (name, items) =
                        segment.split_at(segment.find('[').unwrap_or(segment.len()));
                    (!name.is_empty())
                        .then_some(Step::Field(name))
                        .into_iter()
                        .chain(std::iter::repeat_n(Step::Items, items.len() / 2))
                }) {
                    node = tree.0[node].child(step).unwrap_or_else(|| {
                        let child = tree.0.len();
                        tree.0[node].children.push((step, child));
                        tree.0.push(FieldNode::default());
                        child
                    });
                    tree.0[node].toward_revealed |= revealed;
                }
                tree.0[node].revealed |= revealed;
                tree.0[node].data_keyed_map |= !revealed;
            }
        }
        tree
    }

    /// The position of the value one `step` below a value at `parent`.
    fn step(&self, parent: Position, step: Step<'_>) -> Position {
        let Position::Node(node) = parent else {
            return parent;
        };
        match self.0[node].child(step) {
            Some(child) if self.0[child].revealed => Position::Revealed,
            Some(child) => Position::Node(child),
            None => Position::Outside,
        }
    }

    /// The position of the value under `key` in an object at `object`. The values of a data-keyed
    /// map are one `[]` step below it, whatever their keys.
    fn entry(&self, object: Position, key: &str) -> Position {
        let step = match object {
            Position::Node(node) if self.0[node].data_keyed_map => Step::Items,
            _ => Step::Field(key),
        };
        self.step(object, step)
    }

    /// Whether the key of a value at `value`, in an object at `object`, prints itself. The keys of a
    /// data-keyed map do not, whatever its values reveal.
    fn shows_key(&self, object: Position, value: Position, field_names: bool) -> bool {
        match (object, value) {
            (Position::Revealed, _) => true,
            (Position::Node(node), _) if self.0[node].data_keyed_map => false,
            (_, Position::Revealed) => true,
            (_, Position::Node(node)) if self.0[node].toward_revealed => true,
            _ => field_names,
        }
    }
}

impl FieldNode {
    fn child(&self, step: Step<'_>) -> Option<usize> {
        self.children
            .iter()
            .find(|(child, _)| *child == step)
            .map(|&(_, node)| node)
    }
}

/// What an outline prints of a value without its lengths and counts, hashed, so that the items of
/// an array compare in constant memory. A collision counts an item as one more of the shape before
/// it, which hides the item and reveals nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Shape(u64);

impl Shape {
    fn of(printed: impl Hash) -> Self {
        let mut hasher = DefaultHasher::new();
        printed.hash(&mut hasher);
        Self(hasher.finish())
    }
}

/// The outline of one input as serde_json reads it.
struct Outliner {
    policy: Policy,
    tree: FieldTree,
    text: OutlineText,
}

impl Outliner {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            tree: FieldTree::new(policy),
            text: OutlineText::new(),
        }
    }

    fn outline(mut self, json: &[u8]) -> String {
        if self.policy.sizes {
            self.text.push(&format!(
                "{} {}",
                json.len(),
                plural(json.len(), "byte", "bytes")
            ));
        }
        let mark = self.text.mark();
        let first = json.trim_ascii_start().first().copied();
        let read = matches!(
            first,
            Some(b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n')
        )
        .then(|| {
            self.text.separate(": ");
            let mut deserializer = serde_json::Deserializer::from_slice(json);
            let at = Position::Node(0);
            ValueSeed {
                outliner: &mut self,
                at,
            }
            .deserialize(&mut deserializer)
            .and_then(|_| deserializer.end())
            .err()
        });
        let error = match read {
            Some(error) if error.is_none() || matches!(first, Some(b'{' | b'[' | b'"')) => error,
            // Bytes that do not start as JSON, or a number or a word at the top level that is not
            // all of the input, which is more likely text, hex or base64 than broken JSON.
            _ => {
                self.text.restore(mark);
                self.text.separate(", ");
                self.text.push("not JSON: ");
                self.text.push(input_class(json));
                None
            }
        };
        self.text.end_body();
        if let Some(error) = error {
            self.text.push_space();
            self.text
                .push(&format!("<error: {}>", self.policy.describe(&error)));
        }
        self.text.text
    }

    /// Writes a value the outline hides, of `kind`, and its length in `chars` under `SIZES`.
    fn hidden(&mut self, kind: &str, chars: Option<usize>) -> Shape {
        match chars.filter(|_| self.policy.sizes) {
            Some(chars) => self.text.push(&format!(
                "<{kind}, {chars} {}>",
                plural(chars, "char", "chars")
            )),
            None => self.text.push(&format!("<{kind}>")),
        }
        Shape::of(("hidden", kind))
    }

    /// Writes `text`, a boolean or a number as serde_json writes it, where `at` is revealed.
    fn plain(&mut self, at: Position, kind: &str, text: &str, chars: Option<usize>) -> Shape {
        if !matches!(at, Position::Revealed) {
            return self.hidden(kind, chars);
        }
        self.text.push(text);
        Shape::of(("revealed", text))
    }

    /// Writes `value` quoted and escaped, cut after [`MAX_REVEALED_LEN`] bytes.
    fn quoted(&mut self, value: &str) -> Shape {
        let mut escaped = String::new();
        let mut cut = false;
        for character in value.chars() {
            let fits = escaped.len();
            match character {
                '"' | '\\' => {
                    escaped.push('\\');
                    escaped.push(character);
                }
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                // `<` and `>` are escaped so that a value cannot pass for an annotation.
                ' '..='~' if !matches!(character, '<' | '>') => escaped.push(character),
                other => {
                    for unit in other.encode_utf16(&mut [0; 2]) {
                        escaped.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
            if escaped.len() > MAX_REVEALED_LEN {
                escaped.truncate(fits);
                cut = true;
                break;
            }
        }
        self.text.push(&format!("\"{escaped}\""));
        if cut {
            self.hidden("cut", Some(value.chars().count()));
        }
        Shape::of(("revealed", escaped))
    }
}

/// A value at a position, and the visitor that writes it.
struct ValueSeed<'o> {
    outliner: &'o mut Outliner,
    at: Position,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Shape;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Shape, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Shape;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Shape, E> {
        let text = if value { "true" } else { "false" };
        Ok(self.outliner.plain(self.at, "bool", text, None))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Shape, E> {
        let text = value.to_string();
        Ok(self
            .outliner
            .plain(self.at, "number", &text, Some(text.len())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Shape, E> {
        let text = value.to_string();
        Ok(self
            .outliner
            .plain(self.at, "number", &text, Some(text.len())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Shape, E> {
        let text = serde_json::Number::from_f64(value)
            .map_or_else(|| value.to_string(), |number| number.to_string());
        Ok(self
            .outliner
            .plain(self.at, "number", &text, Some(text.len())))
    }

    fn visit_str<E>(self, value: &str) -> Result<Shape, E> {
        Ok(match self.at {
            Position::Revealed => self.outliner.quoted(value),
            _ => self.outliner.hidden("string", Some(value.chars().count())),
        })
    }

    fn visit_unit<E>(self) -> Result<Shape, E> {
        self.outliner.text.push("null");
        Ok(Shape::of("null"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Shape, A::Error> {
        let Self { outliner, at } = self;
        outliner.text.push("[");
        let item_at = outliner.tree.step(at, Step::Items);
        let mut run = ItemRun::default();
        "[".hash(&mut run.shape);
        loop {
            run.begin(&mut outliner.text);
            let item = ValueSeed {
                outliner: &mut *outliner,
                at: item_at,
            };
            let Some(shape) = items.next_element_seed(item)? else {
                outliner.text.restore(run.mark);
                break;
            };
            run.end(shape, &mut outliner.text);
        }
        run.push_counts(&mut outliner.text);
        outliner.text.push("]");
        Ok(Shape(run.shape.finish()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Shape, A::Error> {
        let Self { outliner, at } = self;
        outliner.text.push("{");
        let mut shape = DefaultHasher::new();
        "{".hash(&mut shape);
        let mut first = true;
        loop {
            let mark = outliner.text.mark();
            if !first {
                outliner.text.push(", ");
            }
            let Some(key) = entries.next_key::<String>()? else {
                outliner.text.restore(mark);
                break;
            };
            first = false;
            let value_at = outliner.tree.entry(at, &key);
            if outliner
                .tree
                .shows_key(at, value_at, outliner.policy.field_names)
            {
                outliner.quoted(&key)
            } else {
                outliner.hidden("key", Some(key.chars().count()))
            }
            .hash(&mut shape);
            outliner.text.push(": ");
            let value = ValueSeed {
                outliner: &mut *outliner,
                at: value_at,
            };
            entries.next_value_seed(value)?.hash(&mut shape);
        }
        outliner.text.push("}");
        Ok(Shape(shape.finish()))
    }
}

/// The items of an array as they are read. Every item is written, and taken back when it has the
/// shape of the item before it or the array already shows [`MAX_ITEMS_SHOWN`], so that an item
/// serde_json stops in stays in the outline.
#[derive(Default)]
struct ItemRun {
    read: usize,
    shown: usize,
    /// The items after the last one shown that have its shape.
    same: usize,
    /// The items past the ones shown and their run.
    more: usize,
    previous: Option<Shape>,
    /// The outline before the item being read.
    mark: Mark,
    shape: DefaultHasher,
}

impl ItemRun {
    fn begin(&mut self, text: &mut OutlineText) {
        self.mark = text.mark();
        self.push_counts(text);
        if self.read > 0 {
            text.push(", ");
        }
    }

    fn end(&mut self, shape: Shape, text: &mut OutlineText) {
        let same = self.previous == Some(shape);
        if (same && self.more == 0) || self.shown >= MAX_ITEMS_SHOWN {
            text.restore(self.mark);
            if same && self.more == 0 {
                self.same += 1;
            } else {
                self.more += 1;
            }
        } else {
            self.same = 0;
            self.shown += 1;
        }
        if !same {
            shape.hash(&mut self.shape);
        }
        self.previous = Some(shape);
        self.read += 1;
    }

    /// Writes the counts of the items not shown.
    fn push_counts(&self, text: &mut OutlineText) {
        if self.same > 0 {
            text.push(&format!(", <{} more of the same shape>", self.same));
        }
        if self.more > 0 {
            text.push(&format!(
                ", <{} more {}>",
                self.more,
                plural(self.more, "item", "items")
            ));
        }
    }
}

/// The outline as it is written: printable ASCII within a budget, which
/// [`end_body`](Self::end_body) raises for the annotations at the end. A write that does not fit is
/// cut, and the writes after it are dropped until the text is restored to a mark before the cut.
struct OutlineText {
    text: String,
    budget: usize,
    cut: bool,
}

/// A length of the outline to restore it to.
#[derive(Clone, Copy, Default)]
struct Mark {
    len: usize,
    cut: bool,
}

impl OutlineText {
    fn new() -> Self {
        Self {
            text: String::new(),
            budget: MAX_OUTLINE_LEN - OUTLINE_END_RESERVE,
            cut: false,
        }
    }

    fn push(&mut self, part: &str) {
        if self.cut {
            return;
        }
        let room = self.budget.saturating_sub(self.text.len());
        // Every part is ASCII, so a cut falls between characters.
        self.text
            .push_str(part.get(..room.min(part.len())).unwrap_or_default());
        self.cut = part.len() > room;
    }

    /// Writes `separator` unless the outline is empty.
    fn separate(&mut self, separator: &str) {
        if !self.text.is_empty() {
            self.push(separator);
        }
    }

    /// Writes the space before an annotation, unless the outline is empty or ends with one.
    fn push_space(&mut self) {
        if !self.text.ends_with(' ') {
            self.separate(" ");
        }
    }

    fn mark(&self) -> Mark {
        Mark {
            len: self.text.len(),
            cut: self.cut,
        }
    }

    fn restore(&mut self, mark: Mark) {
        self.text.truncate(mark.len);
        self.cut = mark.cut;
    }

    /// Ends the body of the outline: notes where it was cut, and opens the reserve for the
    /// annotations of the end.
    fn end_body(&mut self) {
        self.budget = MAX_OUTLINE_LEN;
        if std::mem::take(&mut self.cut) {
            self.push_space();
            self.push("<outline cut>");
        }
    }
}

/// The class of `bytes` that do not start as JSON, which names nothing of them.
fn input_class(bytes: &[u8]) -> &'static str {
    let content = bytes.trim_ascii();
    if bytes.is_empty() {
        "empty"
    } else if content.is_empty() {
        "whitespace only"
    } else if content.iter().all(u8::is_ascii_hexdigit) {
        "hex digits"
    } else if content.iter().all(|byte| {
        // The alphabets of base64 and base64url, the padding, and the line breaks of MIME.
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=' | b'\r' | b'\n')
    }) {
        "base64-like text"
    } else if std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|character| !character.is_control() || character.is_ascii_whitespace())
    }) {
        "text"
    } else {
        "binary data"
    }
}

fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::{Map, Value};

    use super::*;

    /// An invoice whose customer, line descriptions, flag and total no test reveals.
    const INVOICE: &str = r#"{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","lines":[{"description":"Standing desk","quantity":2},{"description":"Cable tray","quantity":4}],"paid":true,"total_cents":117600}"#;

    struct InvoiceLog;

    impl JsonRedaction for InvoiceLog {
        const REVEALED_FIELDS: FieldPaths =
            FieldPaths::from_static(&["number", "currency", "lines[].quantity"]);
    }

    struct InvoiceSizes;

    impl JsonRedaction for InvoiceSizes {
        const SIZES: bool = true;
    }

    /// Uppercase letters that no word of an outline has, so that a secret made of them is found
    /// in an outline only where the outline shows it.
    const SECRET_LETTERS: &str = "ABCDGHIKLMPQRVWXYZ";

    fn outline<P: JsonRedaction>(json: &[u8]) -> String {
        RedactedJson::new::<P>(json).to_string()
    }

    /// The invoice cut inside the key of the second line's quantity.
    fn cut_invoice() -> &'static [u8] {
        &INVOICE.as_bytes()[..INVOICE.rfind("quantity").expect("a second line") + 3]
    }

    #[test]
    fn the_default_policy_shows_the_shape_only() {
        assert_eq!(
            outline::<ShapeOnly>(INVOICE.as_bytes()),
            "{<key>: <string>, <key>: <string>, <key>: <string>, <key>: [{<key>: <string>, <key>: <number>}, <1 more of the same shape>], <key>: <bool>, <key>: <number>}"
        );
        assert_eq!(
            outline::<ShapeOnly>(cut_invoice()),
            "{<key>: <string>, <key>: <string>, <key>: <string>, <key>: [{<key>: <string>, <key>: <number>}, {<key>: <string>, <error: EOF while parsing a string>"
        );
    }

    #[test]
    fn a_revealed_path_shows_its_values_and_the_names_on_the_way() {
        assert_eq!(
            outline::<InvoiceLog>(INVOICE.as_bytes()),
            r#"{"number": "INV-1042", <key>: <string>, "currency": "EUR", "lines": [{<key>: <string>, "quantity": 2}, {<key>: <string>, "quantity": 4}], <key>: <bool>, <key>: <number>}"#
        );
    }

    #[test]
    fn field_names_show_except_the_keys_of_data_keyed_maps() {
        struct AccountLog;

        impl JsonRedaction for AccountLog {
            const FIELD_NAMES: bool = true;
            const DATA_KEYED_MAPS: FieldPaths = FieldPaths::from_static(&["balances"]);
        }

        let account = br#"{"owner":"ann@example.com","balances":{"ann@example.com":10,"bob@example.com":-2}}"#;

        assert_eq!(
            outline::<AccountLog>(account),
            r#"{"owner": <string>, "balances": {<key>: <number>, <key>: <number>}}"#
        );
    }

    #[test]
    fn the_values_of_a_data_keyed_map_are_named_by_items() {
        struct NestedLog;

        impl JsonRedaction for NestedLog {
            const FIELD_NAMES: bool = true;
            const DATA_KEYED_MAPS: FieldPaths =
                FieldPaths::from_static(&["balances", "balances[]"]);
        }

        struct TotalLog;

        impl JsonRedaction for TotalLog {
            const FIELD_NAMES: bool = true;
            const DATA_KEYED_MAPS: FieldPaths = FieldPaths::from_static(&["balances"]);
            const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["balances[].total"]);
        }

        assert_eq!(
            outline::<NestedLog>(br#"{"balances":{"ann@x.com":{"bob@y.com":1}}}"#),
            r#"{"balances": {<key>: {<key>: <number>}}}"#
        );
        assert_eq!(
            outline::<TotalLog>(br#"{"balances":{"ann@x.com":{"total":5,"note":"n"}}}"#),
            r#"{"balances": {<key>: {"total": 5, "note": <string>}}}"#
        );
    }

    #[test]
    fn a_syntax_message_without_the_position_suffix_gives_the_category() {
        let position = " at line 1 column 7";

        assert_eq!(
            Policy::fixed_message(
                Category::Eof,
                "EOF while parsing a list at line 1 column 7",
                position
            ),
            "EOF while parsing a list"
        );
        assert_eq!(
            Policy::fixed_message(Category::Syntax, "invalid number: 4111-1111-1111", position),
            "Syntax error"
        );
    }

    #[test]
    fn sizes_show_lengths_the_byte_count_and_the_error_position() {
        let cut = cut_invoice();

        assert_eq!(
            outline::<InvoiceSizes>(cut),
            format!("{} bytes: {{<key, 6 chars>: <string, 8 chars>, <key, 8 chars>: <string, 17 chars>, <key, 8 chars>: <string, 3 chars>, <key, 5 chars>: [{{<key, 11 chars>: <string, 13 chars>, <key, 8 chars>: <number, 1 char>}}, {{<key, 11 chars>: <string, 10 chars>, <error: EOF while parsing a string at line 1 column {}>", cut.len(), cut.len())
        );
    }

    #[test]
    fn a_revealed_value_is_escaped_into_one_capped_line() {
        struct NoteLog;

        impl JsonRedaction for NoteLog {
            const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["note", "long"]);
        }

        let json = format!(
            "{{\"note\":\"one\\ntwo \\\"quoted\\\" <b> caf\u{e9} \u{2028} \u{1f600}\",\"long\":\"{}\"}}",
            "x".repeat(1000)
        );

        assert_eq!(
            outline::<NoteLog>(json.as_bytes()),
            format!(
                r#"{{"note": "one\ntwo \"quoted\" \u003cb\u003e caf\u00e9 \u2028 \ud83d\ude00", "long": "{}"<cut>}}"#,
                "x".repeat(MAX_REVEALED_LEN)
            )
        );
    }

    #[test]
    fn items_of_the_same_shape_are_counted() {
        struct LinesLog;

        impl JsonRedaction for LinesLog {
            const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["[].quantity"]);
        }

        let line = r#"{"description":"Standing desk","quantity":2}"#;
        let lines = format!("[{}]", vec![line; 100_000].join(","));

        assert_eq!(
            outline::<LinesLog>(lines.as_bytes()),
            r#"[{<key>: <string>, "quantity": 2}, <99999 more of the same shape>]"#
        );
    }

    #[test]
    fn an_array_shows_a_few_items_of_different_shapes() {
        struct ItemsLog;

        impl JsonRedaction for ItemsLog {
            const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["[]"]);
        }

        let quantities =
            serde_json::to_string(&(0..1000).collect::<Vec<u32>>()).expect("numbers serialise");

        assert_eq!(
            outline::<ItemsLog>(quantities.as_bytes()),
            "[0, 1, 2, 3, 4, 5, 6, 7, <992 more items>]"
        );
    }

    #[test]
    fn bytes_that_are_not_json_print_as_their_class() {
        const CARD: &str = "4111 1111 1111 1111";
        let base64 = secret_vault_value::SecretValue::from(CARD)
            .as_sensitive_base64_str()
            .to_string();

        for (input, class) in [
            (base64.as_bytes(), "base64-like text"),
            (b"cafe4111".as_slice(), "hex digits"),
            (CARD.as_bytes(), "text"),
            (b"\x1f\x8b\x08\x00card".as_slice(), "binary data"),
            (b" \n".as_slice(), "whitespace only"),
            (b"".as_slice(), "empty"),
        ] {
            assert_eq!(outline::<ShapeOnly>(input), format!("not JSON: {class}"));
        }
    }

    #[test]
    fn a_long_outline_is_cut_and_still_ends_with_the_error() {
        let entries: Vec<String> = (0..10_000)
            .map(|index| format!("\"field{index}\":{index}"))
            .collect();
        let json = format!("{{{}", entries.join(","));

        let outline = outline::<ShapeOnly>(json.as_bytes());

        assert!(outline.len() <= MAX_OUTLINE_LEN, "{}", outline.len());
        assert!(
            outline.ends_with(" <outline cut> <error: EOF while parsing an object>"),
            "{outline}"
        );
    }

    #[test]
    fn nesting_past_serde_jsons_limit_ends_the_outline() {
        let open = "[".repeat(1_000_000);

        let outline = outline::<ShapeOnly>(open.as_bytes());

        assert_eq!(
            outline,
            format!("{} <error: recursion limit exceeded>", "[".repeat(127))
        );
    }

    #[test]
    fn a_field_path_is_field_names_and_items() {
        for valid in ["number", "lines[].quantity", "[]", "[].id", "matrix[][]"] {
            assert!(FieldPaths::is_field_path(valid.as_bytes()), "{valid}");
        }
        // Empty; an empty field name; `[` without `]`; `]` alone; a name right after `[]`.
        for invalid in ["", "a..b", "a[", "a]", "a[]b"] {
            assert!(!FieldPaths::is_field_path(invalid.as_bytes()), "{invalid}");
        }
    }

    /// A JSON document whose strings, numbers and keys are secrets, and a choice of its paths.
    fn document_and_paths() -> impl Strategy<Value = (Value, Vec<String>)> {
        let secret = proptest::string::string_regex(&format!("[{SECRET_LETTERS}]{{16}}"))
            .expect("a regular expression");
        let key = proptest::string::string_regex(&format!("[{SECRET_LETTERS}]{{12}}"))
            .expect("a regular expression")
            .boxed();
        let leaf = prop_oneof![
            secret.prop_map(Value::String),
            (1_000_000_000_000_u64..10_000_000_000_000).prop_map(Value::from),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
        ];
        let document = leaf.prop_recursive(4, 32, 4, move |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::vec((key.clone(), inner), 0..4)
                    .prop_map(|entries| Value::Object(entries.into_iter().collect::<Map<_, _>>())),
            ]
        });
        document.prop_flat_map(|document| {
            let mut paths = Vec::new();
            collect_paths(&document, "", &mut paths);
            paths.sort();
            paths.dedup();
            let count = paths.len();
            (
                Just(document),
                proptest::sample::subsequence(paths, 0..=count.min(4)),
            )
        })
    }

    /// Every path below `value`, which is at `prefix`.
    fn collect_paths(value: &Value, prefix: &str, paths: &mut Vec<String>) {
        let children: Vec<(String, &Value)> = match value {
            Value::Object(entries) => entries
                .iter()
                .map(|(key, child)| match prefix {
                    "" => (key.clone(), child),
                    prefix => (format!("{prefix}.{key}"), child),
                })
                .collect(),
            Value::Array(items) => items
                .iter()
                .map(|child| (format!("{prefix}[]"), child))
                .collect(),
            _ => Vec::new(),
        };
        for (path, child) in children {
            collect_paths(child, &path, paths);
            paths.push(path);
        }
    }

    /// The secrets of `value` an outline revealing `paths` shows and hides: its strings, the
    /// decimal text of its numbers, and its keys. `paths` are what is left of the revealed paths
    /// below `value`, an empty one when a path ends at it.
    fn secrets(value: &Value, paths: &[&str], shown: &mut Vec<String>, hidden: &mut Vec<String>) {
        let revealed = paths.contains(&"");
        let below = |step: &str| -> Vec<&str> {
            if revealed {
                return vec![""];
            }
            paths
                .iter()
                .filter_map(|path| {
                    let rest = path.strip_prefix(step)?;
                    match rest.strip_prefix('.') {
                        Some(rest) => Some(rest),
                        None => (rest.is_empty() || rest.starts_with('[')).then_some(rest),
                    }
                })
                .collect()
        };
        let secret = match value {
            Value::String(secret) => secret.clone(),
            Value::Number(secret) => secret.to_string(),
            Value::Object(entries) => {
                for (key, child) in entries {
                    let below = below(key);
                    if below.is_empty() {
                        hidden.push(key.clone());
                    } else {
                        shown.push(key.clone());
                    }
                    secrets(child, &below, shown, hidden);
                }
                return;
            }
            Value::Array(items) => {
                let below = below("[]");
                for child in items {
                    secrets(child, &below, shown, hidden);
                }
                return;
            }
            Value::Bool(_) | Value::Null => return,
        };
        if revealed {
            shown.push(secret);
        } else {
            hidden.push(secret);
        }
    }

    /// Whether every digit of `outline` is in a count of items, such as `<3 more items>`, or in
    /// the name of a class of bytes.
    fn digits_are_counts_only(outline: &str) -> bool {
        let is_digit = |character: char| character.is_ascii_digit();
        let outline = outline.replace("base64-like", "");
        outline.match_indices(is_digit).all(|(at, _)| {
            outline[..at].trim_end_matches(is_digit).ends_with('<')
                && outline[at..]
                    .trim_start_matches(is_digit)
                    .starts_with(" more")
        })
    }

    proptest! {
        #[test]
        fn an_outline_shows_nothing_its_policy_does_not_opt_into(
            (document, paths) in document_and_paths(),
            cut in any::<prop::sample::Index>(),
        ) {
            let json = serde_json::to_string(&document)?;
            let cut_json = &json.as_bytes()[..cut.index(json.len() + 1)];
            let leaked: &'static [&'static str] =
                Vec::leak(paths.iter().map(|path| &*String::leak(path.clone())).collect());
            let sizes_and_paths = |json: &[u8]| RedactedJson {
                json,
                policy: Policy {
                    field_names: false,
                    data_keyed_maps: FieldPaths::NONE,
                    sizes: true,
                    revealed_fields: FieldPaths::from_static(leaked),
                },
            }
            .to_string();
            let mut shown = Vec::new();
            let mut hidden = Vec::new();
            secrets(&document, &paths.iter().map(String::as_str).collect::<Vec<_>>(), &mut shown, &mut hidden);

            for shape_only in [outline::<ShapeOnly>(json.as_bytes()), outline::<ShapeOnly>(cut_json)] {
                prop_assert!(digits_are_counts_only(&shape_only), "{}", shape_only);
                prop_assert!(!shape_only.contains(|character| SECRET_LETTERS.contains(character)), "{}", shape_only);
            }
            let whole = sizes_and_paths(json.as_bytes());
            let cut = sizes_and_paths(cut_json);
            for secret in &shown {
                prop_assert!(whole.contains(secret.as_str()), "{} not in {}", secret, whole);
            }
            for secret in &hidden {
                for window in secret.as_bytes().windows(10) {
                    let window = std::str::from_utf8(window)?;
                    prop_assert!(!whole.contains(window), "{} of {} in {}", window, secret, whole);
                    prop_assert!(!cut.contains(window), "{} of {} in {}", window, secret, cut);
                }
            }
        }

        #[test]
        fn any_bytes_outline_as_one_bounded_line_of_printable_ascii(
            input in prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..512),
                "[{}\\[\\],:\"0-9a-z \\\\.eE+\\-\u{e9}\n]{0,256}".prop_map(String::into_bytes),
            ],
        ) {
            for outline in [outline::<ShapeOnly>(&input), outline::<InvoiceLog>(&input), outline::<InvoiceSizes>(&input)] {
                prop_assert!(outline.len() <= MAX_OUTLINE_LEN, "{}", outline.len());
                prop_assert!(outline.bytes().all(|byte| matches!(byte, 0x20..=0x7E)), "{}", outline);
            }
        }
    }
}
