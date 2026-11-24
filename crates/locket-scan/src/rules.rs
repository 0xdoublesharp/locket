//! Provider-token rules, env-file detection, and high-entropy heuristics.

use std::collections::BTreeMap;
use std::ops::AddAssign;
use std::path::Path;

/// Default minimum length for high-entropy token detection.
pub const DEFAULT_MIN_ENTROPY_TOKEN_LEN: usize = 20;

/// Default Shannon entropy threshold in bits per character.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// High-entropy scanner rule thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyRule {
    /// Minimum printable token byte length to consider.
    pub min_len: usize,
    /// Shannon entropy threshold in bits per character.
    pub threshold: f64,
}

impl Default for EntropyRule {
    fn default() -> Self {
        Self { min_len: DEFAULT_MIN_ENTROPY_TOKEN_LEN, threshold: DEFAULT_ENTROPY_THRESHOLD }
    }
}

/// Returns true when `token` matches the default high-entropy fallback rule.
#[must_use]
pub fn is_default_high_entropy_token(token: &str) -> bool {
    is_high_entropy_token_with_rule(token, EntropyRule::default())
}

/// Returns true when `token` is a printable non-whitespace token with Shannon
/// entropy greater than or equal to `threshold`.
#[must_use]
pub fn is_high_entropy_token(token: &str, min_len: usize, threshold: f64) -> bool {
    is_high_entropy_token_with_rule(token, EntropyRule { min_len, threshold })
}

/// Returns true when `token` matches the configured high-entropy fallback rule.
#[must_use]
pub fn is_high_entropy_token_with_rule(token: &str, rule: EntropyRule) -> bool {
    token.len() >= rule.min_len
        && token.chars().all(|character| !character.is_whitespace() && !character.is_control())
        && !is_excluded_public_identifier(token)
        && shannon_entropy(token) >= rule.threshold
}

fn is_excluded_public_identifier(token: &str) -> bool {
    is_uuid_like(token) || is_checksum_like(token) || is_documented_public_id(token)
}

fn is_uuid_like(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn is_checksum_like(token: &str) -> bool {
    matches!(token.len(), 32 | 40 | 64 | 128) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_documented_public_id(token: &str) -> bool {
    token.starts_with("lk_proj_")
        || token.starts_with("lk_prof_")
        || token.starts_with("lk_sec_")
        || token.starts_with("lk_key_")
        || token.starts_with("lkdev2_")
}

/// Computes Shannon entropy in bits per character.
#[must_use]
pub fn shannon_entropy(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }
    let ascii_entropy = u32::try_from(token.len()).map_or_else(
        |_| large_ascii_entropy(token),
        |total| {
            ascii_counts::<u32>(token).map(|counts| {
                // Sum in the same character order as the Unicode path for identical thresholds.
                counts
                    .into_iter()
                    .filter(|&count| count != 0)
                    .map(|count| entropy_contribution(f64::from(count), f64::from(total)))
                    .sum()
            })
        },
    );
    ascii_entropy.unwrap_or_else(|| unicode_shannon_entropy(token))
}

fn ascii_counts<Count>(token: &str) -> Option<[Count; 128]>
where
    Count: Copy + Default + From<u8> + AddAssign,
{
    let mut counts = [Count::default(); 128];
    for byte in token.bytes() {
        *counts.get_mut(usize::from(byte))? += Count::from(1);
    }
    Some(counts)
}

#[allow(clippy::cast_precision_loss)]
fn large_ascii_entropy(token: &str) -> Option<f64> {
    // Wider counters preserve the allocation-free path for inputs over four GiB.
    let total = token.len() as f64;
    Some(
        ascii_counts::<usize>(token)?
            .into_iter()
            .filter(|&count| count != 0)
            .map(|count| entropy_contribution(count as f64, total))
            .sum(),
    )
}

#[allow(clippy::cast_precision_loss)]
fn unicode_shannon_entropy(token: &str) -> f64 {
    let mut counts = BTreeMap::<char, usize>::new();
    let mut total = 0_usize;
    for character in token.chars() {
        *counts.entry(character).or_default() += 1;
        total += 1;
    }

    let total = total as f64;
    counts.values().map(|&count| entropy_contribution(count as f64, total)).sum()
}

fn entropy_contribution(count: f64, total: f64) -> f64 {
    let probability = count / total;
    -probability * probability.log2()
}

/// Returns true when `token` matches a built-in provider prefix rule.
#[must_use]
pub fn is_provider_token(token: &str) -> bool {
    const PROVIDER_PREFIXES: &[&str] = &["sk_live_", "sk_test_", "ghp_", "github_pat_", "xoxb-"];

    PROVIDER_PREFIXES.iter().any(|prefix| token.starts_with(prefix) && token.len() > prefix.len())
}

pub fn is_env_file_label(path_label: &str) -> bool {
    Path::new(path_label)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .is_some_and(|file_name| file_name == ".env" || file_name.starts_with(".env."))
}

#[cfg(test)]
mod tests {
    use super::{is_high_entropy_token, shannon_entropy, unicode_shannon_entropy};

    #[test]
    fn shannon_entropy_matches_character_counts_for_ascii_and_unicode() {
        for token in ["abcdeaabcfgh", "AAAAA", "ABBC🦀🦀ééé", "x \t ñ"] {
            assert_eq!(shannon_entropy(token).to_bits(), unicode_shannon_entropy(token).to_bits());
        }

        assert!(shannon_entropy("").abs() < f64::EPSILON);
        assert!((shannon_entropy("éé🦀🦀") - 1.0).abs() < f64::EPSILON);
        assert!((shannon_entropy("abcd") - 2.0).abs() < f64::EPSILON);
        for token in ["ABCDE", "ABCDEé"] {
            let threshold = shannon_entropy(token);
            assert!(is_high_entropy_token(token, 1, threshold));
            assert!(!is_high_entropy_token(token, 1, threshold.next_up()));
        }
    }
}
