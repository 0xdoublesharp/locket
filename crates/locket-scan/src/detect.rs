//! Internal token tokenization and detection helpers shared by scan and redact.

use crate::FindingKind;
use crate::rules::{EntropyRule, is_high_entropy_token_with_rule, is_provider_token};

#[derive(Debug, Clone, Copy)]
pub struct Detection {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
    pub kind: FindingKind,
}

pub fn sensitive_detections(text: &str) -> Vec<Detection> {
    sensitive_detections_with_entropy_rule(text, EntropyRule::default())
}

pub fn sensitive_detections_with_entropy_rule(
    text: &str,
    entropy_rule: EntropyRule,
) -> Vec<Detection> {
    let mut detections = Vec::new();
    let mut segment = None;
    let mut line = 1;
    let mut column = 1;

    // A final boundary flushes any candidate at end of input.
    for (end, character) in text.char_indices().chain(std::iter::once((text.len(), '\0'))) {
        if is_token_boundary(character) || character.is_whitespace() || character.is_control() {
            if let Some((start, start_column)) = segment.take() {
                let candidate = &text[start..end];
                let kind = if is_provider_token(candidate) {
                    Some(FindingKind::ProviderTokenPattern)
                } else if is_high_entropy_token_with_rule(candidate, entropy_rule) {
                    Some(FindingKind::HighEntropy)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    detections.push(Detection { start, end, line, column: start_column, kind });
                }
            }
        } else {
            segment.get_or_insert((end, column));
        }

        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    detections
}

const fn is_token_boundary(character: char) -> bool {
    matches!(
        character,
        '=' | ':' | '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
    )
}
