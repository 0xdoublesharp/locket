//! Bounded checks of input validation and the composed secret ACL.

use std::path::Path;

use crate::policy::glob_matches;
use crate::{LkReferenceUri, SecretAccessPolicy, SecretName};

#[kani::proof]
#[kani::unwind(6)]
fn bounded_secret_names_match_the_ascii_grammar() {
    // Three bytes cover empty, multi-character ASCII, and 1–3 byte UTF-8
    // sequences without triggering stdlib's 8-byte SWAR UTF-8 validation path.
    let bytes: [u8; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok(input) = std::str::from_utf8(&bytes[..len]) {
        let valid = input.as_bytes().split_first().is_some_and(|(first, rest)| {
            (first.is_ascii_uppercase() || *first == b'_')
                && rest.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        });
        let name = SecretName::new(input);
        assert_eq!(name.is_ok(), valid);
        if let Ok(name) = name {
            assert_eq!(name.as_str(), input);
        }
    }
}

#[kani::proof]
#[kani::unwind(12)]
fn bounded_reference_suffixes_parse_without_panics() {
    // Representative URI alphabet covering every grammar branch: valid secret
    // chars, version delimiters, and query delimiter.
    const ALPHABET: [u8; 6] = *b"A_0@v?";
    let indices: [usize; 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= indices.len());

    let mut suffix_bytes = [0_u8; 2];
    for i in 0..2 {
        kani::assume(indices[i] < ALPHABET.len());
        suffix_bytes[i] = ALPHABET[indices[i]];
    }
    let Ok(suffix) = std::str::from_utf8(&suffix_bytes[..len]) else {
        unreachable!("ASCII alphabet bytes are valid UTF-8");
    };
    let mut input = String::with_capacity(8 + suffix_bytes.len());
    input.push_str("lk://d/K");
    input.push_str(suffix);
    if let Ok(uri) = LkReferenceUri::parse(&input) {
        assert_eq!(uri.profile().as_str(), "d");
        assert!(SecretName::new(uri.key().as_str()).is_ok());
        assert!(uri.version().is_none_or(|version| version.get() > 0));
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn a_single_acl_mismatch_denies_an_explicitly_selected_secret() {
    let Ok(name) = SecretName::new("K") else { unreachable!("valid fixture name") };
    let acl = SecretAccessPolicy {
        name,
        allow_commands: vec!["b:*".to_owned()],
        allow_argv: vec![vec!["t".to_owned(), "**".to_owned(), "r".to_owned()]],
        allow_paths: vec!["s/**".to_owned()],
    };

    let command_matches: bool = kani::any();
    let argv_matches: bool = kani::any();
    let argv_present: bool = kani::any();
    let path_matches: bool = kani::any();
    let command = if command_matches { "b:x" } else { "d" };
    let cwd = Path::new(if path_matches { "s/c" } else { "s-x" });
    let argv = ["t".to_owned(), if argv_matches { "r" } else { "x" }.to_owned()];
    let allowed = acl.allows(command, argv_present.then_some(&argv[..]), cwd);
    assert_eq!(allowed, command_matches && argv_present && argv_matches && path_matches);
}

#[kani::proof]
#[kani::unwind(10)]
fn bounded_acl_matching_is_panic_free() {
    // Prove glob matching terminates without panicking across symbolic bytes,
    // including repeated wildcard backtracking.
    const GLOB_ALPHABET: [u8; 3] = *b"*ab";
    let pat_idx: [usize; 3] = kani::any();
    let val_idx: [usize; 3] = kani::any();
    let pat_len: usize = kani::any();
    let val_len: usize = kani::any();
    kani::assume(pat_len <= pat_idx.len() && val_len <= val_idx.len());

    let mut pat_bytes = [0_u8; 3];
    let mut val_bytes = [0_u8; 3];
    for i in 0..3 {
        kani::assume(pat_idx[i] < GLOB_ALPHABET.len());
        kani::assume(val_idx[i] < GLOB_ALPHABET.len());
        pat_bytes[i] = GLOB_ALPHABET[pat_idx[i]];
        val_bytes[i] = GLOB_ALPHABET[val_idx[i]];
    }
    let (Ok(pattern), Ok(input)) =
        (std::str::from_utf8(&pat_bytes[..pat_len]), std::str::from_utf8(&val_bytes[..val_len]))
    else {
        unreachable!("ASCII glob bytes are valid UTF-8");
    };
    let _ = glob_matches(pattern, input);

    // Also verify SecretAccessPolicy::allows denies missing argv and parent/root escapes.
    let Ok(name) = SecretName::new("K") else { unreachable!("valid fixture name") };
    let acl = SecretAccessPolicy {
        name,
        allow_commands: vec!["*".to_owned()],
        allow_argv: vec![vec!["a*".to_owned(), "**".to_owned()]],
        allow_paths: vec![".".to_owned()],
    };
    let argv = ["ab".to_owned()];
    assert!(!acl.allows("c", None, Path::new("s")));
    assert!(!acl.allows("c", Some(&argv), Path::new("../s")));
    assert!(!acl.allows("c", Some(&argv), Path::new("/s")));
    assert!(acl.allows("c", Some(&argv), Path::new("s/a")));
}
