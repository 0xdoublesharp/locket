//! Bounded XML field extraction for object-store and `WebDAV` listings.

use super::{Result, reject};
use crate::team_sync::SyncError;

pub(super) fn fields(
    bytes: &[u8],
    root: &str,
    select: impl Fn(&[&str]) -> bool,
    mut field: impl FnMut(&[&str], String) -> Result<()>,
) -> Result<()> {
    let mut input = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    input = input.strip_prefix('\u{feff}').unwrap_or(input).trim_start();
    if let Some(declaration) = input.strip_prefix("<?xml ") {
        let (_, remaining) = declaration.split_once("?>").ok_or_else(invalid)?;
        input = remaining;
    }
    let mut stack = Vec::new();
    let mut path = Vec::new();
    let mut capture: Option<String> = None;
    let mut root_seen = false;
    while !input.is_empty() {
        let boundary = input.find('<').unwrap_or(input.len());
        let (text, rest) = input.split_at(boundary);
        if let Some(value) = &mut capture {
            unescape(text, value)?;
        } else if stack.is_empty() && !text.trim().is_empty() {
            return Err(invalid());
        }
        if rest.is_empty() {
            break;
        }
        if let Some(comment) = rest.strip_prefix("<!--") {
            input = comment.split_once("-->").ok_or_else(invalid)?.1;
            continue;
        }
        if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
            let (text, remaining) = cdata.split_once("]]>").ok_or_else(invalid)?;
            if stack.is_empty() {
                return Err(invalid());
            }
            if let Some(value) = &mut capture {
                value.push_str(text);
            }
            input = remaining;
            continue;
        }

        let end = tag_end(rest).ok_or_else(invalid)?;
        let tag = rest[1..end].trim_end();
        input = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            if stack.pop() != Some(name) {
                return Err(invalid());
            }
            if let Some(value) = capture.take() {
                field(&path, value)?;
            }
            path.pop();
            continue;
        }
        if capture.is_some() || stack.len() >= 32 {
            return Err(invalid());
        }
        let empty = tag.ends_with('/');
        let tag = tag.strip_suffix('/').unwrap_or(tag);
        let name = tag.split_ascii_whitespace().next().ok_or_else(invalid)?;
        let local = local_name(name).ok_or_else(invalid)?;
        if stack.is_empty() {
            if root_seen || local != root {
                return Err(invalid());
            }
            root_seen = true;
        }
        path.push(local);
        if select(&path) {
            capture = Some(String::new());
        }
        if empty {
            if let Some(value) = capture.take() {
                field(&path, value)?;
            }
            path.pop();
        } else {
            stack.push(name);
        }
    }
    if !root_seen || !stack.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

fn tag_end(input: &str) -> Option<usize> {
    let mut quote = None;
    for (index, byte) in input.bytes().enumerate().skip(1) {
        match byte {
            byte if quote.is_some() => {
                if quote == Some(byte) {
                    quote = None;
                }
            }
            b'\'' | b'"' => quote = Some(byte),
            b'>' => return Some(index),
            b'<' => return None,
            _ => {}
        }
    }
    None
}

fn local_name(name: &str) -> Option<&str> {
    fn valid(name: &str) -> bool {
        let mut bytes = name.bytes();
        bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    }
    if let Some((prefix, local)) = name.split_once(':') {
        (valid(prefix) && valid(local)).then_some(local)
    } else {
        valid(name).then_some(name)
    }
}

fn unescape(mut text: &str, result: &mut String) -> Result<()> {
    while let Some((before, remainder)) = text.split_once('&') {
        result.push_str(before);
        // A valid predefined or numeric entity is short. Limit the scan
        // before looking for a terminator.
        let end = remainder
            .as_bytes()
            .iter()
            .take(12)
            .position(|byte| *byte == b';')
            .ok_or_else(invalid)?;
        let entity = &remainder[..end];
        text = &remainder[end + 1..];
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let numeric = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16)
                } else {
                    entity.strip_prefix('#').ok_or_else(invalid)?.parse()
                };
                numeric
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|ch| *ch != '\0')
                    .ok_or_else(invalid)?
            }
        };
        result.push(decoded);
    }
    result.push_str(text);
    Ok(())
}

fn invalid() -> SyncError {
    reject("invalid team transport XML listing")
}
