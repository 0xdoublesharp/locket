//! Bounded checks of input validation and the composed secret ACL.

use std::path::Path;

use crate::{LkReferenceUri, PolicyDocument, SecretAccessPolicy, SecretName};

#[kani::proof]
#[kani::unwind(8)]
fn bounded_secret_names_match_the_ascii_grammar() {
    // Four bytes cover empty, multi-character ASCII, and all 1–4 byte UTF-8
    // sequences without triggering stdlib's 8-byte SWAR UTF-8 validation path.
    let bytes: [u8; 4] = kani::any();
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
#[kani::unwind(16)]
fn bounded_reference_suffixes_parse_without_panics() {
    let suffix_bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= suffix_bytes.len());
    kani::assume(suffix_bytes[..len].iter().all(u8::is_ascii));

    let Ok(suffix) = std::str::from_utf8(&suffix_bytes[..len]) else {
        unreachable!("ASCII suffix bytes are valid UTF-8");
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
#[kani::unwind(12)]
fn bounded_acl_matching_is_panic_free() {
    let bytes: [u8; 4] = kani::any();
    kani::assume(bytes.iter().all(u8::is_ascii));
    let split: usize = kani::any();
    kani::assume(split <= bytes.len());
    let (pattern, input) = bytes.split_at(split);
    let (Ok(pattern), Ok(input)) = (std::str::from_utf8(pattern), std::str::from_utf8(input))
    else {
        unreachable!("ASCII slices are valid UTF-8");
    };
    let Ok(name) = SecretName::new("TOKEN") else { unreachable!("valid fixture name") };
    let acl = SecretAccessPolicy {
        name,
        allow_commands: vec!["*".to_owned()],
        allow_argv: vec![vec![pattern.to_owned(), "**".to_owned()]],
        allow_paths: vec![".".to_owned()],
    };
    let argv = [input.to_owned()];
    let _ = acl.allows(input, Some(&argv), Path::new(input));
    assert!(!acl.allows(input, None, Path::new(input)));
    assert!(!acl.allows(input, Some(&argv), Path::new("../src")));
}
