//! Python JSON containers in a flat arena: parsing, traversal and drop never recurse.
use super::statement_tokens::{self, Token, Tokens};
use indexmap::IndexMap;
/// Inclusive container depth, counting arrays, objects and an empty root container.
pub const MAX_CONTAINER_DEPTH: usize = 256;

#[derive(Clone, Debug)]
pub enum Node {
    Null,
    Bool(bool),
    Integer(String),
    Float(f64),
    String(Vec<u32>),
    Array(Vec<usize>),
    Object(IndexMap<Vec<u32>, usize>),
}
#[derive(Clone, Debug)]
pub struct Document {
    nodes: Vec<Node>,
    root: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Invalid,
    IntegerLimit,
    ExtraData,
    NestingLimit,
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
}
impl Document {
    pub fn root(&self) -> &Node {
        &self.nodes[self.root]
    }
    pub fn node(&self, id: usize) -> &Node {
        &self.nodes[id]
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let tokens = Tokens::from_bytes(bytes).ok_or(Error::Encoding)?;
        let mut nodes = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();
        let mut root = None;
        for token in tokens {
            // Even an invalid token after a complete value is Python's Extra data.
            if root.is_some() && stack.is_empty() {
                return Err(Error::ExtraData);
            }
            let token = token.map_err(|error| match error {
                statement_tokens::Error::Invalid => Error::Invalid,
                statement_tokens::Error::IntegerLimit => Error::IntegerLimit,
            })?;
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
                            return Err(Error::Invalid);
                        }
                        frame.state = if object { State::Key } else { State::Value };
                        continue;
                    }
                    State::Colon => {
                        if !matches!(token, Token::Punctuation(b':')) {
                            return Err(Error::Invalid);
                        }
                        frame.state = State::Value;
                        continue;
                    }
                    State::First | State::Key if object => {
                        let Token::String(key) = token else {
                            return Err(Error::Invalid);
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
                _ => return Err(Error::Invalid),
            };
            let container = matches!(node, Node::Array(_) | Node::Object(_));
            if container && stack.len() >= MAX_CONTAINER_DEPTH {
                return Err(Error::NestingLimit);
            }
            let id = nodes.len();
            nodes.push(node);
            if let Some(frame) = stack.last_mut() {
                match &mut nodes[frame.id] {
                    Node::Array(values) => values.push(id),
                    Node::Object(values) => {
                        // IndexMap replaces the value without moving the original key.
                        values.insert(frame.key.take().ok_or(Error::Invalid)?, id);
                    }
                    _ => unreachable!(),
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
                });
            }
        }
        if !stack.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            nodes,
            root: root.ok_or(Error::Invalid)?,
        })
    }
}

#[cfg(test)]
#[path = "statement_document_tests.rs"]
mod tests;
