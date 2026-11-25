//! Bounded checks of input validation and the composed secret ACL.

use std::path::Path;

use crate::policy::glob_matches;
use crate::{LkReferenceUri, PolicyDocument, SecretAccessPolicy, SecretName};

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
#[kani::unwind(18)]
fn bounded_reference_suffixes_parse_without_panics() {
    // Representative URI alphabet covering every grammar branch: valid secret
    // start/rest chars, invalid chars, and all URI/version/query delimiters.
    const ALPHABET: [u8; 12] = *b"A_01a-@v?&=/";
    let indices: [usize; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= indices.len());

    let mut suffix_bytes = [0_u8; 4];
    for i in 0..4 {
        kani::assume(indices[i] < ALPHABET.len());
        suffix_bytes[i] = ALPHABET[indices[i]];
    }
    let Ok(suffix) = std::str::from_utf8(&suffix_bytes[..len]) else {
        unreachable!("ASCII alphabet bytes are valid UTF-8");
    };
    let mut input = String::with_capacity(9 + suffix_bytes.len());
    input.push_str("lk://dev/");
    input.push_str(suffix);
    if let Ok(uri) = LkReferenceUri::parse(&input) {
        assert_eq!(uri.profile().as_str(), "dev");
        assert!(SecretName::new(uri.key().as_str()).is_ok());
        assert!(uri.version().is_none_or(|version| version.get() > 0));
    }
}

#[kani::proof]
#[kani::unwind(24)]
fn a_single_acl_mismatch_denies_an_explicitly_selected_secret() {
    let Ok(name) = SecretName::new("TOKEN") else { unreachable!("valid fixture name") };
    let document = PolicyDocument {
        schema_version: 1,
        variables: Default::default(),
        commands: Default::default(),
        path_scopes: Default::default(),
        secret_access: [(
            name.as_str().to_owned(),
            SecretAccessPolicy {
                name: name.clone(),
                allow_commands: vec!["build:*".to_owned()],
                allow_argv: vec![vec!["tool".to_owned(), "**".to_owned(), "run".to_owned()]],
                allow_paths: vec!["src/**".to_owned()],
            },
        )]
        .into(),
    };

    let command_matches: bool = kani::any();
    let argv_matches: bool = kani::any();
    let argv_present: bool = kani::any();
    let path_matches: bool = kani::any();
    let command = if command_matches { "build:release" } else { "deploy" };
    let cwd = Path::new(if path_matches { "src/child" } else { "src-sibling" });
    let argv = ["tool".to_owned(), if argv_matches { "run" } else { "test" }.to_owned()];
    let selected = [name];
    let denied =
        document.denied_secrets(command, argv_present.then_some(&argv[..]), cwd, &selected);
    assert_eq!(denied.is_empty(), command_matches && argv_present && argv_matches && path_matches);
}

#[kani::proof]
#[kani::unwind(20)]
fn bounded_acl_matching_is_panic_free() {
    // Prove glob matching terminates without panicking across symbolic bytes,
    // including repeated wildcard backtracking.
    const GLOB_ALPHABET: [u8; 4] = *b"*a/b";
    let pat_idx: [usize; 4] = kani::any();
    let val_idx: [usize; 4] = kani::any();
    let pat_len: usize = kani::any();
    let val_len: usize = kani::any();
    kani::assume(pat_len <= pat_idx.len() && val_len <= val_idx.len());

    let mut pat_bytes = [0_u8; 4];
    let mut val_bytes = [0_u8; 4];
    for i in 0..4 {
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

    // Also verify SecretAccessPolicy::allows denies missing argv and any
    // parent-escaping or absolute path across all representative shapes.
    let Ok(name) = SecretName::new("TOKEN") else { unreachable!("valid fixture name") };
    let acl = SecretAccessPolicy {
        name,
        allow_commands: vec!["*".to_owned()],
        allow_argv: vec![vec!["a*".to_owned(), "**".to_owned()]],
        allow_paths: vec![".".to_owned()],
    };
    let argv = ["ab".to_owned()];
    let escaped_idx: usize = kani::any();
    kani::assume(escaped_idx < 3);
    let escaped = ["../src", "/src", "src/../src"][escaped_idx];
    assert!(!acl.allows("cmd", None, Path::new("src")));
    assert!(!acl.allows("cmd", Some(&argv), Path::new(escaped)));
    assert!(acl.allows("cmd", Some(&argv), Path::new("src/sub")));
}
