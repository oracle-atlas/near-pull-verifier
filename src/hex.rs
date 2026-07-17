//! Hex decoding.
//!
//! A small, hand-rolled `0x`-hex-to-bytes decoder — no external crate, to keep
//! the wasm small and dependencies minimal.

use near_sdk::{env, require};

/// Decode a `0x`-prefixed hex string into bytes (upper- or lower-case digits).
///
/// # Arguments
/// * `hex_str` - the hex string to decode; must be `0x`-prefixed
///
/// # Panics
/// Panics if the `0x` prefix is missing, the length is odd, or a character is
/// not a valid hex digit.
pub(crate) fn from_hex(hex_str: &str) -> Vec<u8> {
    let digits = match hex_str.strip_prefix("0x") {
        Some(rest) => rest,
        None => env::panic_str("Hex string must start with 0x"),
    };
    require!(
        digits.len().is_multiple_of(2),
        "Hex string must have even length"
    );
    let mut out = Vec::with_capacity(digits.len() / 2);
    let bytes = digits.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]);
        let lo = hex_val(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Convert one ASCII hex digit to its value 0–15. Panics on a non-hex byte.
#[inline]
fn hex_val(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => env::panic_str("Invalid hex character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_hex {
        use super::*;

        #[test]
        fn roundtrip() {
            let bytes = vec![0x00, 0x12, 0xab, 0xff, 0x7f];
            // `hex::encode` produces the no-prefix lowercase hex we prepend `0x` to.
            assert_eq!(from_hex(&format!("0x{}", hex::encode(&bytes))), bytes);
        }

        #[test]
        fn accepts_0x_prefix() {
            assert_eq!(from_hex("0xabcd"), vec![0xab, 0xcd]);
        }

        #[test]
        fn accepts_uppercase_digits() {
            assert_eq!(from_hex("0xABCD"), vec![0xab, 0xcd]);
            assert_eq!(from_hex("0xaBcD"), vec![0xab, 0xcd]);
        }

        #[test]
        fn empty_body_returns_empty() {
            // Just the prefix with no digits decodes to an empty byte vector.
            assert_eq!(from_hex("0x"), Vec::<u8>::new());
        }

        #[test]
        #[should_panic(expected = "Hex string must start with 0x")]
        fn rejects_uppercase_0x_prefix() {
            // Only the lowercase `0x` prefix is accepted; `0X` is rejected.
            let _ = from_hex("0XABCD");
        }

        #[test]
        #[should_panic(expected = "Hex string must start with 0x")]
        fn missing_prefix_fails() {
            let _ = from_hex("00ff");
        }

        #[test]
        #[should_panic(expected = "Hex string must start with 0x")]
        fn empty_string_fails() {
            let _ = from_hex("");
        }

        #[test]
        #[should_panic(expected = "Hex string must have even length")]
        fn odd_length_fails() {
            let _ = from_hex("0xabc");
        }

        #[test]
        #[should_panic(expected = "Invalid hex character")]
        fn invalid_char_fails() {
            let _ = from_hex("0xzz");
        }
    }

    mod hex_val {
        use super::*;

        #[test]
        fn maps_digits() {
            assert_eq!(hex_val(b'0'), 0);
            assert_eq!(hex_val(b'9'), 9);
            assert_eq!(hex_val(b'a'), 10);
            assert_eq!(hex_val(b'f'), 15);
            assert_eq!(hex_val(b'A'), 10);
            assert_eq!(hex_val(b'F'), 15);
        }

        #[test]
        #[should_panic(expected = "Invalid hex character")]
        fn rejects_non_hex() {
            let _ = hex_val(b'g');
        }
    }
}
