//! Strict, bounded JSON decoding shared by validation and evidence inspection.

use serde_json::{Map, Value};

pub(crate) const MAX_DEPTH: usize = 512;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DecodeError {
    #[error("invalid JSON at line {line}, column {column}")]
    InvalidJson { line: usize, column: usize },
    #[error("duplicate JSON object key")]
    DuplicateKey { key: String },
    #[error("expected exactly one JSON document")]
    MultipleDocuments,
    #[error("JSON nesting exceeds {limit} levels")]
    DepthExceeded { limit: usize },
}

enum State {
    KeyOrEnd,
    Key,
    Colon,
    ValueOrEnd,
    Value,
    CommaOrEnd,
}

struct Frame {
    value: Value,
    state: State,
    key: Option<String>,
}

/// Decode exactly one value, rejecting duplicate decoded keys at every level.
/// Container parsing is iterative so the depth limit does not depend on stack size.
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut parser = Parser { bytes, position: 0 };
    let mut frames: Vec<Frame> = Vec::new();
    let mut document = None;

    loop {
        parser.whitespace();
        let next = parser.bytes.get(parser.position).copied();
        if let Some(frame) = frames.last_mut() {
            match frame.state {
                State::KeyOrEnd | State::Key => {
                    if next == Some(b'}') && matches!(frame.state, State::KeyOrEnd) {
                        parser.position += 1;
                        let value = frames.pop().expect("open container").value;
                        attach(value, &mut frames, &mut document);
                        continue;
                    }
                    if next != Some(b'"') {
                        return Err(parser.invalid());
                    }
                    let key = parser.string()?;
                    if frame
                        .value
                        .as_object()
                        .expect("object frame")
                        .contains_key(&key)
                    {
                        return Err(DecodeError::DuplicateKey { key });
                    }
                    frame.key = Some(key);
                    frame.state = State::Colon;
                    continue;
                }
                State::Colon => {
                    if next != Some(b':') {
                        return Err(parser.invalid());
                    }
                    parser.position += 1;
                    frame.state = State::Value;
                    continue;
                }
                State::CommaOrEnd => {
                    let object = frame.value.is_object();
                    if next == Some(if object { b'}' } else { b']' }) {
                        parser.position += 1;
                        let value = frames.pop().expect("open container").value;
                        attach(value, &mut frames, &mut document);
                        continue;
                    }
                    if next != Some(b',') {
                        return Err(parser.invalid());
                    }
                    parser.position += 1;
                    frame.state = if object { State::Key } else { State::Value };
                    continue;
                }
                State::ValueOrEnd if next == Some(b']') => {
                    parser.position += 1;
                    let value = frames.pop().expect("open container").value;
                    attach(value, &mut frames, &mut document);
                    continue;
                }
                State::ValueOrEnd | State::Value => {}
            }
        } else if let Some(value) = document {
            return if next.is_none() {
                Ok(value)
            } else {
                Err(DecodeError::MultipleDocuments)
            };
        }

        // The root has depth zero, matching the Go decoder's value-depth limit.
        if frames.len() > MAX_DEPTH {
            return Err(DecodeError::DepthExceeded { limit: MAX_DEPTH });
        }
        match next {
            Some(b'{') | Some(b'[') => {
                let object = next == Some(b'{');
                parser.position += 1;
                frames.push(Frame {
                    value: if object {
                        Value::Object(Map::new())
                    } else {
                        Value::Array(Vec::new())
                    },
                    state: if object {
                        State::KeyOrEnd
                    } else {
                        State::ValueOrEnd
                    },
                    key: None,
                });
            }
            Some(b'"') => {
                let value = Value::String(parser.string()?);
                attach(value, &mut frames, &mut document);
            }
            Some(b'n' | b't' | b'f' | b'-' | b'0'..=b'9') => {
                let start = parser.position;
                while let Some(byte) = parser.bytes.get(parser.position) {
                    if byte.is_ascii_whitespace() || matches!(byte, b',' | b']' | b'}') {
                        break;
                    }
                    parser.position += 1;
                }

                let value = serde_json::from_slice(&bytes[start..parser.position])
                    .map_err(|_| parser.invalid())?;
                attach(value, &mut frames, &mut document);
            }
            _ => return Err(parser.invalid()),
        }
    }
}

fn attach(value: Value, frames: &mut [Frame], document: &mut Option<Value>) {
    if let Some(frame) = frames.last_mut() {
        match &mut frame.value {
            Value::Object(object) => {
                object.insert(frame.key.take().expect("decoded object key"), value);
            }
            Value::Array(array) => array.push(value),
            _ => unreachable!("container frame"),
        }
        frame.state = State::CommaOrEnd;
    } else {
        *document = Some(value);
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }

    fn invalid(&self) -> DecodeError {
        let prefix = &self.bytes[..self.position];
        DecodeError::InvalidJson {
            line: prefix.iter().filter(|&&byte| byte == b'\n').count() + 1,
            column: prefix
                .iter()
                .rev()
                .take_while(|&&byte| byte != b'\n')
                .count()
                + 1,
        }
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let start = self.position;
        self.position += 1;

        while let Some(&byte) = self.bytes.get(self.position) {
            self.position += 1;
            match byte {
                b'\\' => {
                    if self.position < self.bytes.len() {
                        self.position += 1;
                    }
                }
                b'"' => {
                    return serde_json::from_slice(&self.bytes[start..self.position])
                        .map_err(|_| self.invalid());
                }
                _ => {}
            }
        }

        Err(self.invalid())
    }
}

#[cfg(test)]
mod tests {

    use crate::bom::validation::{ValidationError, Validator};
    use crate::json::{DecodeError, decode};
    use serde_json::json;
    use std::sync::OnceLock;
    fn validator() -> &'static Validator {
        static VALIDATOR: OnceLock<Validator> = OnceLock::new();

        VALIDATOR.get_or_init(|| Validator::new().expect("embedded schemas compile offline"))
    }

    #[test]
    fn duplicate_keys_are_typed_and_escape_aware() {
        for input in [
            r#"{"name":null,"name":"safe"}"#,
            r#"{"outer":[{"name":"secret","na\u006de":"safe"}]}"#,
            r#"{"outer":{"\u006eame":1,"name":2}}"#,
        ] {
            assert_eq!(
                decode(input.as_bytes()),
                Err(DecodeError::DuplicateKey {
                    key: "name".to_owned()
                })
            );
            assert!(
                matches!(validator().validate(input.as_bytes(), false), Err(ValidationError::Decode(DecodeError::DuplicateKey { key })) if key == "name")
            );
        }

        assert_eq!(
            decode(br#"{"a":1,"b":{"a":2},"c":{"a":3}}"#).unwrap(),
            json!({"a":1,"b":{"a":2},"c":{"a":3}})
        );
    }

    #[test]
    fn rejects_trailing_documents_and_malformed_json() {
        for input in ["{} {}", "{} null", "{} garbage", "null true"] {
            assert_eq!(
                decode(input.as_bytes()),
                Err(DecodeError::MultipleDocuments)
            );
        }

        for input in [
            "",
            "{",
            "[",
            r#"{"x":1,}"#,
            "[1,]",
            "[1 2]",
            r#"{"x" 1}"#,
            "01",
            "1e",
            "NaN",
            r#""\uD800""#,
            "\"unterminated",
            "[truefalse]",
            "[\u{b}]",
            r#"{"x":}"#,
        ] {
            assert!(
                matches!(
                    decode(input.as_bytes()),
                    Err(DecodeError::InvalidJson { .. })
                ),
                "{input:?}"
            );
        }

        assert!(matches!(
            decode(b"\"\xff\""),
            Err(DecodeError::InvalidJson { .. })
        ));

        assert_eq!(
            decode(b" \n [true, false, null, -1.5e2, \"a\\\"b\"]\t").unwrap(),
            json!([true, false, null, -150.0, "a\"b"])
        );
    }

    #[test]
    fn depth_limit_is_explicit_and_exceeds_serde_default() {
        let accepted = format!("{}0{}", "[".repeat(512), "]".repeat(512));
        assert!(decode(accepted.as_bytes()).is_ok());

        let rejected = format!("{}0{}", "[".repeat(513), "]".repeat(513));
        assert_eq!(
            decode(rejected.as_bytes()),
            Err(DecodeError::DepthExceeded { limit: 512 })
        );

        let rejected = format!("{}{}", "[".repeat(514), "]".repeat(514));
        assert_eq!(
            decode(rejected.as_bytes()),
            Err(DecodeError::DepthExceeded { limit: 512 })
        );
    }
}
