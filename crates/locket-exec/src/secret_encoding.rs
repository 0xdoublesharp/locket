use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, Encoding, HEXLOWER, HEXUPPER,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Eq, PartialEq)]
/// Supported byte representations of a secret or placeholder.
pub enum Form {
    /// Unchanged bytes.
    Raw,
    /// Percent-encoded reserved bytes with uppercase digits.
    Url,
    /// Percent-encoded reserved bytes with lowercase digits.
    UrlLower,
    /// Every byte percent-encoded with uppercase digits.
    UrlFull,
    /// Every byte percent-encoded with lowercase digits.
    UrlFullLower,
    /// Standard Base64 with padding.
    Base64,
    /// Standard Base64 without padding.
    Base64Unpadded,
    /// URL-safe Base64 with padding.
    Base64Url,
    /// URL-safe Base64 without padding.
    Base64UrlUnpadded,
    /// JSON string contents with unescaped UTF-8.
    Json,
    /// JSON string contents with non-ASCII characters escaped.
    JsonAscii,
}

impl Form {
    pub(super) const BASE64_FORMS: [Self; 4] =
        [Self::Base64, Self::Base64Unpadded, Self::Base64Url, Self::Base64UrlUnpadded];

    pub(super) const ALL: [Self; 11] = [
        Self::Raw,
        Self::Url,
        Self::UrlLower,
        Self::UrlFull,
        Self::UrlFullLower,
        Self::Base64,
        Self::Base64Unpadded,
        Self::Base64Url,
        Self::Base64UrlUnpadded,
        Self::Json,
        Self::JsonAscii,
    ];

    pub(super) fn encode(self, value: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Raw => Zeroizing::new(value.to_vec()),
            Self::Url => percent_encode(value, false, &HEXUPPER),
            Self::UrlLower => percent_encode(value, false, &HEXLOWER),
            Self::UrlFull => percent_encode(value, true, &HEXUPPER),
            Self::UrlFullLower => percent_encode(value, true, &HEXLOWER),
            Self::Base64 => encode(&BASE64, value),
            Self::Base64Unpadded => encode(&BASE64_NOPAD, value),
            Self::Base64Url => encode(&BASE64URL, value),
            Self::Base64UrlUnpadded => encode(&BASE64URL_NOPAD, value),
            Self::Json => json_escape(value, false),
            Self::JsonAscii => json_escape(value, true),
        }
    }
}

/// Encodes bytes directly into zeroizing storage.
pub fn encode(encoding: &Encoding, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(vec![0; encoding.encode_len(value.len())]);
    encoding.encode_mut(value, &mut output);
    output
}

const fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn percent_encode(value: &[u8], all: bool, hex: &Encoding) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() * 3));
    for byte in value {
        if !all && unreserved(*byte) {
            output.push(*byte);
        } else {
            output.extend_from_slice(b"%00");
            let end = output.len();
            hex.encode_mut(std::slice::from_ref(byte), &mut output[end - 2..]);
        }
    }
    output
}

fn json_escape(value: &[u8], ascii_only: bool) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() * 6));
    if let Some(text) = ascii_only.then(|| std::str::from_utf8(value).ok()).flatten() {
        let mut units = Zeroizing::new([0_u16; 2]);
        for character in text.chars() {
            if character.is_ascii() {
                push_json_byte(&mut output, character as u8);
            } else {
                for unit in character.encode_utf16(&mut *units) {
                    output.extend_from_slice(br"\u0000");
                    let end = output.len();
                    HEXLOWER.encode_mut(&unit.to_be_bytes(), &mut output[end - 4..]);
                }
            }
        }
    } else {
        for byte in value {
            push_json_byte(&mut output, *byte);
        }
    }
    output
}

fn push_json_byte(output: &mut Vec<u8>, byte: u8) {
    match byte {
        b'"' => output.extend_from_slice(br#"\""#),
        b'\\' => output.extend_from_slice(br"\\"),
        b'\n' => output.extend_from_slice(br"\n"),
        b'\r' => output.extend_from_slice(br"\r"),
        b'\t' => output.extend_from_slice(br"\t"),
        8 => output.extend_from_slice(br"\b"),
        12 => output.extend_from_slice(br"\f"),
        0..=31 => {
            output.extend_from_slice(br"\u0000");
            let end = output.len();
            HEXLOWER.encode_mut(std::slice::from_ref(&byte), &mut output[end - 2..]);
        }
        _ => output.push(byte),
    }
}
