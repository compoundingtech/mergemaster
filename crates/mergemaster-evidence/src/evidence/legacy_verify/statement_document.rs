//! Python JSON containers in a flat arena: parsing, traversal and drop never recurse.
//! CPython 3.14.7 syntax kind/positions are reported without changing acceptance.
//! Grammar lookahead precedes tokenization, preserving delimiter/extra-data errors
//! even when the following token itself is malformed. Resource limits stay distinct.
pub use super::statement_tokens::Error as TextError;
pub use super::statement_tokens::{SyntaxError, SyntaxKind};
use super::statement_tokens::{Token, Tokens};
use indexmap::IndexMap;
/// Inclusive container depth, counting arrays, objects and an empty root container.
pub const MAX_CONTAINER_DEPTH: usize = 256;

#[derive(Debug)]
pub enum Node {
    Null,
    Bool(bool),
    Integer(String),
    Float(f64),
    String(Vec<u32>),
    Array(Vec<usize>),
    Object(IndexMap<Vec<u32>, usize>),
}
#[derive(Debug)]
pub struct Document {
    nodes: Vec<Node>,
    root: usize,
}
const _: () = {
    assert!(std::mem::size_of::<Node>() <= 80);
    assert!(std::mem::size_of::<Document>() <= 32);
    assert!(std::mem::size_of::<std::sync::Arc<Document>>() <= 8);
};
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Syntax(SyntaxError),
    IntegerLimit { digits: usize },
    NestingLimit,
}
impl From<TextError> for Error {
    fn from(error: TextError) -> Self {
        match error {
            TextError::Syntax(error) => Self::Syntax(error),
            TextError::IntegerLimit { digits } => Self::IntegerLimit { digits },
        }
    }
}
#[derive(Clone, Copy)]
enum State {
    First,
    Key,
    Colon,
    Value,
    After,
}
struct Frame {
    id: usize,
    state: State,
    key: Option<Vec<u32>>,
    comma: usize,
}
impl Document {
    /// Two units/node, four/object entry, one/text point, integer digit or array index.
    /// Includes duplicate-key orphan nodes; conservative retained allocation charge.
    pub(super) fn ownership_units(&self) -> usize {
        2 * self.nodes.len()
            + self
                .nodes
                .iter()
                .map(|node| match node {
                    Node::String(text) => text.len(),
                    Node::Integer(text) => text.len(),
                    Node::Array(items) => items.len(),
                    Node::Object(items) => {
                        4 * items.len() + items.keys().map(Vec::len).sum::<usize>()
                    }
                    _ => 0,
                })
                .sum::<usize>()
    }
    pub fn root(&self) -> &Node {
        &self.nodes[self.root]
    }
    pub fn node(&self, id: usize) -> &Node {
        &self.nodes[id]
    }
    pub fn try_node(&self, id: usize) -> Option<&Node> {
        self.nodes.get(id)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with_depth_limit(bytes, Some(MAX_CONTAINER_DEPTH))
    }
    /// Policy ingress has no fixed depth cap; statement callers retain 256.
    /// Parsing and drop use flat node IDs, never recursive containers.
    pub fn from_bytes_with_depth_limit(
        bytes: &[u8],
        max_depth: Option<usize>,
    ) -> Result<Self, Error> {
        let tokens = Tokens::from_bytes(bytes).ok_or(Error::Encoding)?;
        Self::from_limited_tokens(tokens, max_depth)
    }
    /// JSON str input is already decoded; never strip BOM or detect UTF-16/32.
    pub fn from_text_with_depth_limit(text: &str, max_depth: Option<usize>) -> Result<Self, Error> {
        Self::from_limited_tokens(Self::text_tokens(text)?, max_depth)
    }
    /// Uncapped JSON str parsing cannot fail decoding or exceed a depth budget.
    pub fn from_text(text: &str) -> Result<Self, TextError> {
        Self::from_tokens(Self::text_tokens(text)?, |_| Ok(()))
    }
    fn text_tokens(text: &str) -> Result<Tokens, TextError> {
        if text.starts_with('\u{feff}') {
            return Err(TextError::Syntax(SyntaxError {
                kind: SyntaxKind::UnexpectedUtf8Bom,
                pos: 0,
                lineno: 1,
                colno: 1,
            }));
        }
        Ok(Tokens::from_text(text))
    }
    fn from_limited_tokens(tokens: Tokens, max_depth: Option<usize>) -> Result<Self, Error> {
        Self::from_tokens(tokens, |depth| {
            if max_depth.is_some_and(|limit| depth >= limit) {
                Err(Error::NestingLimit)
            } else {
                Ok(())
            }
        })
    }
    fn from_tokens<E: From<TextError>>(
        mut tokens: Tokens,
        depth_check: impl Fn(usize) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut nodes = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();
        let mut root = None;
        loop {
            let point = tokens.peek();
            let pos = tokens.position();
            let syntax = |kind, at| E::from(TextError::Syntax(tokens.syntax_error(kind, at)));
            if root.is_some() && stack.is_empty() {
                if point.is_some() {
                    return Err(syntax(SyntaxKind::ExtraData, pos));
                }
                break;
            }
            if let Some(frame) = stack.last() {
                let object = matches!(nodes[frame.id], Node::Object(_));
                let close = if object { 125 } else { 93 };
                let expected = match frame.state {
                    State::After if point != Some(44) && point != Some(close) => {
                        Some(SyntaxKind::CommaDelimiter)
                    }
                    State::Colon if point != Some(58) => Some(SyntaxKind::ColonDelimiter),
                    State::Key | State::Value
                        if point == Some(close)
                            && (!object || matches!(frame.state, State::Key)) =>
                    {
                        return Err(syntax(
                            if object {
                                SyntaxKind::TrailingObjectComma
                            } else {
                                SyntaxKind::TrailingArrayComma
                            },
                            frame.comma,
                        ));
                    }
                    State::First | State::Key
                        if object
                            && point != Some(34)
                            && !(matches!(frame.state, State::First) && point == Some(close)) =>
                    {
                        Some(SyntaxKind::PropertyName)
                    }
                    _ => None,
                };
                if let Some(kind) = expected {
                    return Err(syntax(kind, pos));
                }
            }
            let Some(token) = tokens.next() else {
                return Err(TextError::Syntax(
                    tokens.syntax_error(SyntaxKind::ExpectingValue, pos),
                )
                .into());
            };
            let token = token.map_err(E::from)?;
            if let Some(frame) = stack.last_mut() {
                let object = matches!(nodes[frame.id], Node::Object(_));
                let close = if object { b'}' } else { b']' };
                if matches!(frame.state, State::First | State::After)
                    && matches!(&token, Token::Punctuation(p) if *p == close)
                {
                    stack.pop();
                    continue;
                }
                match frame.state {
                    State::After => {
                        if !matches!(token, Token::Punctuation(b',')) {
                            return Err(TextError::Syntax(
                                tokens.syntax_error(SyntaxKind::CommaDelimiter, pos),
                            )
                            .into());
                        }
                        frame.state = if object { State::Key } else { State::Value };
                        frame.comma = pos;
                        continue;
                    }
                    State::Colon => {
                        if !matches!(token, Token::Punctuation(b':')) {
                            return Err(TextError::Syntax(
                                tokens.syntax_error(SyntaxKind::ColonDelimiter, pos),
                            )
                            .into());
                        }
                        frame.state = State::Value;
                        continue;
                    }
                    State::First | State::Key if object => {
                        let Token::String(key) = token else {
                            return Err(TextError::Syntax(
                                tokens.syntax_error(SyntaxKind::PropertyName, pos),
                            )
                            .into());
                        };
                        frame.key = Some(key);
                        frame.state = State::Colon;
                        continue;
                    }
                    _ => {}
                }
            }
            let node = match token {
                Token::Null => Node::Null,
                Token::Bool(v) => Node::Bool(v),
                Token::Integer(mut v) => {
                    if v == "-0" {
                        v.remove(0);
                    }
                    Node::Integer(v)
                }
                Token::Float(v) => Node::Float(v),
                Token::String(v) => Node::String(v),
                Token::Punctuation(b'[') => Node::Array(Vec::new()),
                Token::Punctuation(b'{') => Node::Object(IndexMap::new()),
                _ => {
                    return Err(TextError::Syntax(
                        tokens.syntax_error(SyntaxKind::ExpectingValue, pos),
                    )
                    .into());
                }
            };
            let container = matches!(node, Node::Array(_) | Node::Object(_));
            if container {
                depth_check(stack.len())?;
            }
            let id = nodes.len();
            nodes.push(node);
            if let Some(frame) = stack.last_mut() {
                match &mut nodes[frame.id] {
                    Node::Array(values) => values.push(id),
                    Node::Object(values) => {
                        // IndexMap replaces the value without moving the original key.
                        let key = frame.key.take().ok_or_else(|| {
                            E::from(TextError::Syntax(
                                tokens.syntax_error(SyntaxKind::PropertyName, pos),
                            ))
                        })?;
                        values.insert(key, id);
                    }
                    _ => {
                        return Err(TextError::Syntax(
                            tokens.syntax_error(SyntaxKind::ExpectingValue, pos),
                        )
                        .into());
                    }
                }
                frame.state = State::After;
            } else {
                root = Some(id);
            }
            if container {
                stack.push(Frame {
                    id,
                    state: State::First,
                    key: None,
                    comma: 0,
                });
            }
        }
        Ok(Self {
            nodes,
            root: root.ok_or_else(|| {
                E::from(TextError::Syntax(
                    tokens.syntax_error(SyntaxKind::ExpectingValue, tokens.position()),
                ))
            })?,
        })
    }
}

#[cfg(test)]
#[path = "statement_document_tests.rs"]
mod tests;
