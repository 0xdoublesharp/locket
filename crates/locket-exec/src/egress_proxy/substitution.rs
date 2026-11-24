use std::collections::BTreeSet;

use data_encoding::{BASE64, BASE64_NOPAD, Encoding};
use zeroize::Zeroizing;

use super::destination::Authority;
use super::{EgressBlockReason, Rejection, State};
use crate::secret_encoding::{Form, encode};

pub(super) struct Placeholder(Vec<(Form, Zeroizing<Vec<u8>>)>);

impl Placeholder {
    pub(super) fn new(raw: &[u8]) -> Self {
        let mut variants = vec![(Form::Raw, Form::Raw.encode(raw))];
        for form in Form::BASE64_FORMS {
            let bytes = form.encode(raw);
            if !variants.iter().any(|(_, previous)| *previous == bytes) {
                variants.push((form, bytes));
            }
        }
        Self(variants)
    }

    pub(super) fn raw(&self) -> &[u8] {
        &self.0[0].1
    }

    fn at(&self, input: &[u8]) -> Option<(usize, Form, bool)> {
        self.0
            .iter()
            .filter_map(|(form, bytes)| {
                let consumed = matches_percent_encoded(input, bytes)?;
                Some((consumed, *form, consumed != bytes.len()))
            })
            .max_by_key(|(length, _, _)| *length)
    }
}

fn matches_percent_encoded(input: &[u8], pattern: &[u8]) -> Option<usize> {
    if input.starts_with(pattern) {
        return Some(pattern.len());
    }
    if input.len() < pattern.len() {
        return None;
    }
    let mut offset = 0;
    for byte in pattern {
        match input.get(offset..)? {
            [b'%', high, low, ..] if hex(*high)? << 4 | hex(*low)? == *byte => offset += 3,
            [first, ..] if first == byte => offset += 1,
            _ => return None,
        }
    }
    Some(offset)
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct Match {
    offset: usize,
    length: usize,
    binding: usize,
    form: Form,
    percent_encoded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Field {
    Target,
    Header,
    Body,
}

impl State {
    fn placeholder_matches<'a>(&'a self, bytes: &'a [u8]) -> impl Iterator<Item = Match> + 'a {
        bytes
            .iter()
            .enumerate()
            .filter(|(_, first)| matches!(**first, b'l' | b'b' | b'%'))
            .flat_map(move |(offset, _)| {
                self.bindings.iter().enumerate().filter_map(move |(binding, value)| {
                    let (length, form, percent_encoded) = value.placeholder.at(&bytes[offset..])?;
                    Some(Match { offset, length, binding, form, percent_encoded })
                })
            })
    }

    pub(super) fn contains_placeholder(&self, bytes: &[u8]) -> bool {
        self.placeholder_matches(bytes).next().is_some()
    }

    fn guard_match(&self, matched: Match, destination: &Authority) -> Result<(), Rejection> {
        if self.bindings[matched.binding].hosts.iter().any(|rule| rule.matches(destination)) {
            Ok(())
        } else {
            Err(Rejection {
                reason: EgressBlockReason::HostNotAllowed,
                binding: Some(matched.binding),
            })
        }
    }

    fn guard_credential(&self, bytes: &[u8]) -> Result<(), Rejection> {
        if self.proxy_credentials.contains(bytes) {
            Err(EgressBlockReason::ProxyCredential.into())
        } else {
            Ok(())
        }
    }

    pub(super) fn guard_structure(
        &self,
        bytes: &[u8],
        destination: &Authority,
    ) -> Result<(), Rejection> {
        self.guard_credential(bytes)?;
        let mut found = false;
        for matched in self.placeholder_matches(bytes) {
            self.guard_match(matched, destination)?;
            found = true;
        }
        if found { Err(EgressBlockReason::InvalidRequest.into()) } else { Ok(()) }
    }

    pub(super) fn rewrite(
        &self,
        bytes: &[u8],
        field: Field,
        limit: usize,
        destination: &Authority,
        used: &mut BTreeSet<usize>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Rejection> {
        self.guard_credential(bytes)?;
        let invalid = EgressBlockReason::InvalidRequest;
        let mut edits = Vec::new();
        let mut length = bytes.len();
        let mut cursor = 0;
        for matched in self.placeholder_matches(bytes) {
            // Check every occurrence, including overlaps, before forwarding.
            self.guard_match(matched, destination)?;
            if matched.offset < cursor {
                return Err(invalid.into());
            }
            let secret = self.bindings[matched.binding].value.as_bytes();
            if field == Field::Header && secret.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
                return Err(invalid.into());
            }
            let replacement = match matched.form {
                Form::Raw if matched.percent_encoded || field == Field::Target => {
                    Form::Url.encode(secret)
                }
                form if matched.percent_encoded => Form::Url.encode(&form.encode(secret)),
                form => form.encode(secret),
            };
            length = length
                .checked_sub(matched.length)
                .and_then(|length| length.checked_add(replacement.len()))
                .filter(|length| *length <= limit)
                .ok_or(invalid)?;
            cursor = matched.offset + matched.length;
            used.insert(matched.binding);
            edits.push((matched, replacement));
        }
        if edits.is_empty() {
            return Ok(None);
        }
        let mut rewritten = Zeroizing::new(Vec::with_capacity(length));
        cursor = 0;
        for (matched, replacement) in edits {
            rewritten.extend_from_slice(&bytes[cursor..matched.offset]);
            rewritten.extend_from_slice(&replacement);
            cursor = matched.offset + matched.length;
        }
        rewritten.extend_from_slice(&bytes[cursor..]);
        Ok(Some(rewritten))
    }

    pub(super) fn rewrite_basic(
        &self,
        bytes: &[u8],
        destination: &Authority,
        used: &mut BTreeSet<usize>,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Rejection> {
        let Some(token) = super::wire::basic_payload(bytes) else {
            return Ok(None);
        };
        let decoded = [BASE64, BASE64_NOPAD]
            .into_iter()
            .find_map(|encoding| decode(&encoding, token).map(|value| (encoding, value)));
        let Some((encoding, decoded)) = decoded else {
            return Ok(None);
        };
        let Some(value) = self.rewrite(&decoded, Field::Header, limit, destination, used)? else {
            return Ok(None);
        };
        let encoded = encode(&encoding, &value);
        if encoded.len() > limit - b"Basic ".len() {
            return Err(EgressBlockReason::InvalidRequest.into());
        }
        let mut header = Zeroizing::new(Vec::with_capacity(b"Basic ".len() + encoded.len()));
        header.extend_from_slice(b"Basic ");
        header.extend_from_slice(&encoded);
        Ok(Some(header))
    }
}

fn decode(encoding: &Encoding, input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(vec![0; encoding.decode_len(input.len()).ok()?]);
    let count = encoding.decode_mut(input, &mut output).ok()?;
    output.truncate(count);
    Some(output)
}
