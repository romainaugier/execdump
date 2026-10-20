/*
 * GDB/MI output: records of a kind (^ result, * exec, = notify, ~ console) and a class (done, running,
 * stopped...), then results name=value where a value is a C string, a tuple {name=value,...} or a list
 * [value,...] or [name=value,...]
 */

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Tuple(Vec<(String, Value)>),
    List(Vec<Value>),
}

impl Value {
    pub fn get(&self, name: &str) -> Option<&Value> {
        return match self {
            Value::Tuple(fields) => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
            _ => None,
        };
    }

    pub fn str(&self) -> Option<&str> {
        return match self {
            Value::Str(text) => Some(text),
            _ => None,
        };
    }

    pub fn items(&self) -> &[Value] {
        return match self {
            Value::List(items) => items,
            _ => &[],
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub token: Option<u64>,
    /// ^ * + = ~ @ &
    pub kind: char,
    /// done, running, error, stopped... (the text of the stream records)
    pub class: String,
    pub results: Value,
}

impl Record {
    pub fn get(&self, name: &str) -> Option<&Value> {
        return self.results.get(name);
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        return self.get(name).and_then(Value::str);
    }
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        return self.text.get(self.pos).copied();
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            return true;
        }

        return false;
    }

    fn name(&mut self) -> String {
        let start = self.pos;

        while self.peek().is_some_and(|c| c != b'=' && c != b',' && c != b'}' && c != b']') {
            self.pos += 1;
        }

        return String::from_utf8_lossy(&self.text[start..self.pos]).to_string();
    }

    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }

        let mut bytes = Vec::new();

        loop {
            let c = self.peek()?;
            self.pos += 1;

            match c {
                b'"' => break,
                b'\\' => {
                    let escaped = self.peek()?;
                    self.pos += 1;

                    match escaped {
                        b'n' => bytes.push(b'\n'),
                        b't' => bytes.push(b'\t'),
                        b'r' => bytes.push(b'\r'),
                        b'0'..=b'7' => {
                            let mut value = (escaped - b'0') as u32;

                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        value = value * 8 + (d - b'0') as u32;
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }

                            bytes.push(value as u8);
                        }
                        other => bytes.push(other),
                    }
                }
                other => bytes.push(other),
            }
        }

        return Some(String::from_utf8_lossy(&bytes).to_string());
    }

    fn value(&mut self) -> Option<Value> {
        return match self.peek()? {
            b'"' => self.string().map(Value::Str),
            b'{' => {
                self.pos += 1;
                let fields = self.results(b'}')?;
                Some(Value::Tuple(fields))
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();

                while !self.eat(b']') {
                    // A list of values, or of results: name=value
                    if matches!(self.peek()?, b'"' | b'{' | b'[') {
                        items.push(self.value()?);
                    } else {
                        let name = self.name();
                        self.eat(b'=');
                        items.push(Value::Tuple(vec![(name, self.value()?)]));
                    }

                    self.eat(b',');
                }

                Some(Value::List(items))
            }
            _ => None,
        };
    }

    fn results(&mut self, end: u8) -> Option<Vec<(String, Value)>> {
        let mut fields = Vec::new();

        while self.peek().is_some() && !self.eat(end) {
            let name = self.name();

            if !self.eat(b'=') {
                return None;
            }

            fields.push((name, self.value()?));
            self.eat(b',');
        }

        return Some(fields);
    }
}

/// A line of output of gdb, None for the prompt and what is not a record
pub fn parse(line: &str) -> Option<Record> {
    let line = line.trim_end();
    let digits = line.bytes().take_while(|c| c.is_ascii_digit()).count();
    let token = line[..digits].parse().ok();
    let rest = &line[digits..];
    let kind = rest.chars().next()?;

    if !"^*+=~@&".contains(kind) {
        return None;
    }

    let body = &rest[1..];

    if matches!(kind, '~' | '@' | '&') {
        let mut parser = Parser { text: body.as_bytes(), pos: 0 };
        return Some(Record { token, kind, class: parser.string().unwrap_or_default(), results: Value::Tuple(Vec::new()) });
    }

    let (class, results) = body.split_once(',').unwrap_or((body, ""));
    let mut parser = Parser { text: results.as_bytes(), pos: 0 };
    let fields = parser.results(0).unwrap_or_default();

    return Some(Record { token, kind, class: class.to_string(), results: Value::Tuple(fields) });
}

/// C string of MI (the arguments of the commands)
pub fn quote(text: &str) -> String {
    let mut out = String::from("\"");

    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }

    out.push('"');
    return out;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let stopped = parse(r#"*stopped,reason="breakpoint-hit",disp="keep",bkptno="2",frame={addr="0x00005555555551b6",func="greet",args=[]},thread-id="1""#).unwrap();
        assert_eq!((stopped.kind, stopped.class.as_str(), stopped.str("reason")), ('*', "stopped", Some("breakpoint-hit")));
        assert_eq!(stopped.get("frame").and_then(|f| f.get("addr")).and_then(Value::str), Some("0x00005555555551b6"));

        let frames = parse(r#"7^done,stack=[frame={level="0",addr="0x1",func="a"},frame={level="1",addr="0x2",func="b"}]"#).unwrap();
        assert_eq!(frames.token, Some(7));
        let stack = frames.get("stack").unwrap().items();
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[1].get("frame").and_then(|f| f.get("func")).and_then(Value::str), Some("b"));

        let names = parse(r#"^done,register-names=["rax","rbx",""]"#).unwrap();
        assert_eq!(names.get("register-names").unwrap().items(), &[Value::Str("rax".into()), Value::Str("rbx".into()), Value::Str(String::new())]);

        let console = parse(r#"~"Breakpoint 2, \"x\"\tat\n""#).unwrap();
        assert_eq!((console.kind, console.class.as_str()), ('~', "Breakpoint 2, \"x\"\tat\n"));

        assert_eq!(parse("(gdb)"), None);
        assert_eq!(parse("3^error,msg=\"No symbol\"").unwrap().str("msg"), Some("No symbol"));
        assert_eq!(quote("a \"b\"\\c"), r#""a \"b\"\\c""#);
    }
}
