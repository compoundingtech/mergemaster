//! Python 3.14.7 textwrap defaults for the fixed ASCII help metadata only.
//! User-controlled program text never enters this ASCII-specialized wrapper.
use std::collections::VecDeque;

fn letter(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}
fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn punctuation(byte: u8) -> bool {
    word(byte) || b"!\"'&.,?".contains(&byte)
}

fn split_word<'a>(text: &'a str, chunks: &mut VecDeque<&'a str>) {
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'-' {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < bytes.len() && bytes[end] == b'-' {
            end += 1;
        }
        if end - at >= 2
            && at > 0
            && punctuation(bytes[at - 1])
            && bytes.get(end).is_some_and(|b| word(*b))
        {
            if start < at {
                chunks.push_back(&text[start..at]);
            }
            chunks.push_back(&text[at..end]);
            start = end;
            at = end;
            continue;
        }
        // textwrap.wordsep_re's two letter lookbehinds and letter -? letter
        // lookahead. A hyphen alone is not automatically a wrapping boundary.
        let before = (at >= 2 && letter(bytes[at - 2]) && letter(bytes[at - 1]))
            || (at >= 3 && letter(bytes[at - 3]) && bytes[at - 2] == b'-' && letter(bytes[at - 1]));
        let after = bytes.get(at + 1).is_some_and(|b| letter(*b))
            && (bytes.get(at + 2).is_some_and(|b| letter(*b))
                || (bytes.get(at + 2) == Some(&b'-')
                    && bytes.get(at + 3).is_some_and(|b| letter(*b))));
        if before && after {
            chunks.push_back(&text[start..at + 1]);
            start = at + 1;
        }
        at += 1;
    }
    if start < text.len() {
        chunks.push_back(&text[start..]);
    }
}

pub(super) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut chunks = VecDeque::new();
    // argparse first collapses ASCII whitespace and strips its fixed metadata.
    for (index, token) in text.split_ascii_whitespace().enumerate() {
        if index > 0 {
            chunks.push_back(" ");
        }
        split_word(token, &mut chunks);
    }
    let mut lines = Vec::new();
    while !chunks.is_empty() {
        let mut line = Vec::new();
        let mut length = 0;
        if !lines.is_empty() && chunks.front() == Some(&" ") {
            chunks.pop_front();
        }
        while let Some(&chunk) = chunks.front() {
            if length + chunk.len() > width {
                break;
            }
            chunks.pop_front();
            line.push(chunk);
            length += chunk.len();
        }
        if let Some(front) = chunks.front_mut() {
            let chunk = *front;
            let available = width - length;
            if chunk.len() > width && available > 0 {
                let mut end = available;
                if let Some(hyphen) = chunk[..available].rfind('-')
                    && hyphen > 0
                    && chunk[..hyphen].bytes().any(|b| b != b'-')
                {
                    end = hyphen + 1;
                }
                line.push(&chunk[..end]);
                *front = &chunk[end..];
            }
        }
        if line.last() == Some(&" ") {
            line.pop();
        }
        if !line.is_empty() {
            lines.push(line.concat());
        }
    }
    lines
}
