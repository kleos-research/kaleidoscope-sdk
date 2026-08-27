//! Removing one node from a JSON document without reformatting the rest.
//!
//! WHY THIS EXISTS. Teardown of a manager-owned entry used to parse the file,
//! delete the entry from the parsed value and re-encode the WHOLE document.
//! For a file the manager wrote that is invisible, because the manager wrote it
//! in `to_vec_pretty` form to begin with. For a file the USER wrote it is not:
//! adoption takes ownership of a hand-written entry without touching a byte, so
//! the first time the manager writes that file is the teardown that removes the
//! entry -- and it came back four-space indentation flattened to two, with
//! every inline array exploded across lines. Measured on a `.mcp.json` whose
//! only manager-owned key was `mcpServers.kaleidoscope`: an unrelated `github`
//! entry the manager never owned was rewritten with it.
//!
//! `restore: "structural", formatting: "normalized"` reported that honestly,
//! and honest is not the same as acceptable. The reversibility claim this
//! project makes is byte-exactness, and "we told you we would mangle it" is a
//! disclosure, not a guarantee.
//!
//! HOW IT IS SAFE. This module never decides WHAT to remove. The caller does
//! that with the ordinary parse-remove path it already trusted, and hands both
//! documents in; `removal_path` recovers which single node disappeared, the
//! scanner finds that node's byte span in the ORIGINAL text, and the span is
//! cut out. The result is then parsed and compared against the caller's own
//! `after` document. A mismatch, an unrecognised diff shape, an escape the
//! scanner cannot place -- any of them returns `None` and the caller falls back
//! to re-encoding. So the worst case is exactly today's behaviour, and the best
//! case is that the user's file comes back byte-identical minus one entry.

use serde_json::Value;

/// One step of the path to the removed node.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    Key(String),
    Index(usize),
}

/// `text` minus the one node that `before` holds and `after` does not.
///
/// `None` whenever anything is not provably safe, which the caller must treat
/// as "re-encode instead" rather than as an error.
#[must_use]
pub fn excise(text: &str, before: &Value, after: &Value) -> Option<String> {
    if before == after {
        return None;
    }
    let path = removal_path(before, after)?;
    let (start, end) = span_of(text, &path)?;
    let mut out = String::with_capacity(text.len());
    out.push_str(text.get(..start)?);
    out.push_str(text.get(end..)?);
    // THE PROOF, and the reason this module is allowed to exist at all: the
    // trusted document is the caller's, and a textual edit is accepted only
    // when re-parsing it reproduces that document exactly.
    let reparsed: Value = serde_json::from_str(&out).ok()?;
    (reparsed == *after).then_some(out)
}

/// Which single node `after` is missing, or `None` if the difference is not
/// exactly one removal.
fn removal_path(before: &Value, after: &Value) -> Option<Vec<Segment>> {
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            if a.keys().any(|key| !b.contains_key(key)) {
                return None;
            }
            let removed: Vec<&String> = b.keys().filter(|key| !a.contains_key(*key)).collect();
            let changed: Vec<&String> = b
                .iter()
                .filter(|(key, value)| a.get(*key).is_some_and(|other| other != *value))
                .map(|(key, _)| key)
                .collect();
            match (removed.len(), changed.len()) {
                (1, 0) => Some(vec![Segment::Key(removed[0].clone())]),
                (0, 1) => {
                    let key = changed[0].clone();
                    let mut path = removal_path(b.get(&key)?, a.get(&key)?)?;
                    path.insert(0, Segment::Key(key));
                    Some(path)
                }
                _ => None,
            }
        }
        (Value::Array(b), Value::Array(a)) => {
            if b.len() == a.len() {
                let differing: Vec<usize> = (0..b.len())
                    .filter(|index| b[*index] != a[*index])
                    .collect();
                if differing.len() != 1 {
                    return None;
                }
                let index = differing[0];
                let mut path = removal_path(&b[index], &a[index])?;
                path.insert(0, Segment::Index(index));
                return Some(path);
            }
            if b.len() != a.len() + 1 {
                return None;
            }
            (0..b.len()).find_map(|index| {
                let mut trial = b.clone();
                trial.remove(index);
                (trial == *a).then(|| vec![Segment::Index(index)])
            })
        }
        _ => None,
    }
}

/// Where the addressed member/element sits, and what has to go with it.
struct Hit {
    /// First byte of the member (its key quote) or element.
    start: usize,
    /// One past the last byte of its value.
    end: usize,
    /// First byte of its value, for descending.
    value_start: usize,
    /// The enclosing `{`/`[` and its partner.
    open: usize,
    close: usize,
    /// How many members/elements the enclosing container has.
    count: usize,
}

struct Scanner<'a> {
    bytes: &'a [u8],
    at: usize,
}

const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

impl Scanner<'_> {
    fn space(&mut self) {
        while self.bytes.get(self.at).copied().is_some_and(is_space) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.peek()? == byte).then(|| self.at += 1)
    }

    /// Advance past a string literal, returning its span INCLUDING both quotes.
    fn string(&mut self) -> Option<(usize, usize)> {
        let start = self.at;
        self.eat(b'"')?;
        loop {
            match self.peek()? {
                b'\\' => self.at += 2,
                b'"' => {
                    self.at += 1;
                    return Some((start, self.at));
                }
                _ => self.at += 1,
            }
        }
    }

    /// Advance past any value. Structure only -- numbers and literals are
    /// consumed by their terminator set, because the document has already been
    /// parsed by `serde_json` and is known to be well formed.
    fn value(&mut self) -> Option<()> {
        self.space();
        match self.peek()? {
            b'"' => {
                self.string()?;
                Some(())
            }
            b'{' | b'[' => {
                let open = self.peek()?;
                let close = if open == b'{' { b'}' } else { b']' };
                self.at += 1;
                let mut depth = 1usize;
                while depth > 0 {
                    match self.peek()? {
                        b'"' => {
                            self.string()?;
                        }
                        byte if byte == open => {
                            depth += 1;
                            self.at += 1;
                        }
                        byte if byte == close => {
                            depth -= 1;
                            self.at += 1;
                        }
                        _ => self.at += 1,
                    }
                }
                Some(())
            }
            _ => {
                while self.peek().is_some_and(|byte| {
                    !is_space(byte) && byte != b',' && byte != b'}' && byte != b']'
                }) {
                    self.at += 1;
                }
                Some(())
            }
        }
    }

    /// Walk the container at the cursor, returning the addressed member.
    fn enter(&mut self, text: &str, segment: &Segment) -> Option<Hit> {
        self.space();
        let open = self.at;
        let (opener, closer) = match segment {
            Segment::Key(_) => (b'{', b'}'),
            Segment::Index(_) => (b'[', b']'),
        };
        self.eat(opener)?;
        let mut count = 0usize;
        let mut found: Option<(usize, usize, usize)> = None;
        let close;
        loop {
            self.space();
            if self.peek()? == closer {
                close = self.at;
                self.at += 1;
                break;
            }
            let start = self.at;
            let matches = match segment {
                Segment::Key(wanted) => {
                    let (quote_start, quote_end) = self.string()?;
                    self.space();
                    self.eat(b':')?;
                    // Decoded by `serde_json` itself rather than by a hand
                    // written unescaper, so `"\u006bey"` and `"key"` compare
                    // equal exactly as the parser saw them.
                    let key: String =
                        serde_json::from_str(text.get(quote_start..quote_end)?).ok()?;
                    key == *wanted
                }
                Segment::Index(wanted) => count == *wanted,
            };
            self.space();
            let value_start = self.at;
            self.value()?;
            let end = self.at;
            if matches && found.is_none() {
                found = Some((start, end, value_start));
            }
            count += 1;
            self.space();
            match self.peek()? {
                b',' => self.at += 1,
                byte if byte == closer => {
                    close = self.at;
                    self.at += 1;
                    break;
                }
                _ => return None,
            }
        }
        let (start, end, value_start) = found?;
        Some(Hit {
            start,
            end,
            value_start,
            open,
            close,
            count,
        })
    }
}

/// The byte range to delete for `path`, comma and orphaned indentation included.
fn span_of(text: &str, path: &[Segment]) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut scanner = Scanner { bytes, at: 0 };
    let mut hit = None;
    for (depth, segment) in path.iter().enumerate() {
        let found = scanner.enter(text, segment)?;
        if depth + 1 == path.len() {
            hit = Some(found);
            break;
        }
        scanner.at = found.value_start;
    }
    let hit = hit?;
    // SOLE MEMBER. Cutting just the member would leave `{\n    \n}` -- the
    // indentation of a line that no longer has anything on it. Take the whole
    // interior instead, which yields `{}`.
    if hit.count == 1 {
        return Some((hit.open + 1, hit.close));
    }
    let mut end = hit.end;
    let mut cursor = end;
    while cursor < hit.close && is_space(bytes[cursor]) {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b',') {
        cursor += 1;
        while cursor < hit.close && is_space(bytes[cursor]) {
            cursor += 1;
        }
        end = cursor;
        return Some((hit.start, end));
    }
    // LAST MEMBER: there is no comma after it, so the one BEFORE it is the one
    // that becomes dangling.
    let mut start = hit.start;
    while start > hit.open + 1 && is_space(bytes[start - 1]) {
        start -= 1;
    }
    if bytes.get(start.checked_sub(1)?) == Some(&b',') {
        return Some((start - 1, end));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn removed(text: &str, remove: impl FnOnce(&mut Value)) -> Option<String> {
        let before: Value = serde_json::from_str(text).unwrap();
        let mut after = before.clone();
        remove(&mut after);
        excise(text, &before, &after)
    }

    #[test]
    fn preserves_four_space_indentation_and_inline_arrays() {
        let text = "{\n    \"mcpServers\": {\n        \"github\": {\"command\": \"gh\", \"args\": [\"--x\"]},\n        \"kaleidoscope\": {\"command\": \"kscope\"}\n    }\n}\n";
        let out = removed(text, |value| {
            value["mcpServers"]
                .as_object_mut()
                .unwrap()
                .remove("kaleidoscope");
        })
        .unwrap();
        assert_eq!(
            out,
            "{\n    \"mcpServers\": {\n        \"github\": {\"command\": \"gh\", \"args\": [\"--x\"]}\n    }\n}\n"
        );
    }

    #[test]
    fn removes_a_leading_member_and_the_comma_after_it() {
        let text = "{\n  \"a\": 1,\n  \"b\": 2\n}\n";
        let out = removed(text, |value| {
            value.as_object_mut().unwrap().remove("a");
        })
        .unwrap();
        assert_eq!(out, "{\n  \"b\": 2\n}\n");
    }

    #[test]
    fn a_sole_member_leaves_an_empty_object_not_dangling_whitespace() {
        let text = "{\n  \"only\": {\"x\": 1}\n}\n";
        let out = removed(text, |value| {
            value.as_object_mut().unwrap().remove("only");
        })
        .unwrap();
        assert_eq!(out, "{}\n");
    }

    #[test]
    fn removes_an_array_element_between_two_others() {
        let text = "[\n  1,\n  2,\n  3\n]\n";
        let out = removed(text, |value| {
            value.as_array_mut().unwrap().remove(1);
        })
        .unwrap();
        assert_eq!(out, "[\n  1,\n  3\n]\n");
    }

    #[test]
    fn removes_a_nested_array_element_and_keeps_siblings_verbatim() {
        let text = "{\n\t\"permissions\": {\"allow\": [\"Bash(*)\"]},\n\t\"hooks\": {\n\t\t\"SessionStart\": [\n\t\t\t{\"a\": 1},\n\t\t\t{\"b\": 2}\n\t\t]\n\t}\n}";
        let out = removed(text, |value| {
            value["hooks"]["SessionStart"]
                .as_array_mut()
                .unwrap()
                .remove(0);
        })
        .unwrap();
        assert_eq!(
            out,
            "{\n\t\"permissions\": {\"allow\": [\"Bash(*)\"]},\n\t\"hooks\": {\n\t\t\"SessionStart\": [\n\t\t\t{\"b\": 2}\n\t\t]\n\t}\n}"
        );
    }

    #[test]
    fn a_pruned_ancestor_is_cut_at_the_ancestor() {
        let text = "{\n  \"keep\": 1,\n  \"hooks\": {\n    \"SessionStart\": [\n      {\"only\": true}\n    ]\n  }\n}\n";
        let out = removed(text, |value| {
            value.as_object_mut().unwrap().remove("hooks");
        })
        .unwrap();
        assert_eq!(out, "{\n  \"keep\": 1\n}\n");
    }

    #[test]
    fn escaped_keys_compare_by_their_decoded_value() {
        let text = "{\"\\u006beep\": 1, \"drop\": 2}";
        let out = removed(text, |value| {
            value.as_object_mut().unwrap().remove("drop");
        })
        .unwrap();
        assert_eq!(out, "{\"\\u006beep\": 1}");
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap(),
            json!({"keep": 1})
        );
    }

    #[test]
    fn a_key_whose_value_contains_braces_in_a_string_is_not_miscounted() {
        let text = "{\"a\": \"}{,\", \"kaleidoscope\": {\"x\": \"]\"}, \"b\": 1}";
        let out = removed(text, |value| {
            value.as_object_mut().unwrap().remove("kaleidoscope");
        })
        .unwrap();
        assert_eq!(out, "{\"a\": \"}{,\", \"b\": 1}");
    }

    #[test]
    fn refuses_when_the_difference_is_not_one_removal() {
        let before = json!({"a": 1, "b": 2});
        let after = json!({"a": 9});
        assert!(excise("{\"a\": 1, \"b\": 2}", &before, &after).is_none());
    }

    #[test]
    fn refuses_an_addition() {
        let before = json!({"a": 1});
        let after = json!({"a": 1, "b": 2});
        assert!(excise("{\"a\": 1}", &before, &after).is_none());
    }

    #[test]
    fn refuses_when_before_and_after_are_equal() {
        let before = json!({"a": 1});
        assert!(excise("{\"a\": 1}", &before, &before).is_none());
    }

    #[test]
    fn duplicate_keys_in_the_source_are_refused_rather_than_half_removed() {
        // `serde_json` keeps the LAST duplicate, so the scanner's first match
        // is not necessarily the one the parsed document represents. The
        // re-parse check catches it; this pins that it does.
        let text = "{\"k\": 1, \"k\": 2, \"other\": 3}";
        let before: Value = serde_json::from_str(text).unwrap();
        let mut after = before.clone();
        after.as_object_mut().unwrap().remove("k");
        assert!(excise(text, &before, &after).is_none());
    }
}
