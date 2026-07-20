//! Shared types, constants, and helpers used across the verifier.

use near_sdk::{json_types::U128, near, require};

use crate::hex::from_hex;

/// Length of an EVM address in bytes: the last 20 bytes of `keccak256(pubkey)`,
/// i.e. `keccak256(pubkey)[12..]`.
pub(crate) const EVM_ADDRESS_LEN: usize = 20;

/// Length in bytes of the uncompressed secp256k1 public key returned by
/// `ecrecover`, without the leading `0x04` tag (64 bytes = X || Y).
pub(crate) const SECP256K1_PUBLIC_KEY_LEN: usize = 64;

/// A 20-byte EVM address: `keccak256(pubkey)[12..]`.
pub(crate) type EvmAddress = [u8; EVM_ADDRESS_LEN];

/// Parse a hex string into a 20-byte EVM address. The input must be `0x`-prefixed.
pub(crate) fn parse_evm_address(hex_str: &str) -> EvmAddress {
    let bytes = from_hex(hex_str);
    require!(
        bytes.len() == EVM_ADDRESS_LEN,
        "Signer address must be 20 bytes"
    );
    let mut out = [0u8; EVM_ADDRESS_LEN];
    out.copy_from_slice(&bytes);
    out
}

/// An uncompressed secp256k1 public key without the leading `0x04` tag
/// (64 bytes = X || Y), as returned by `ecrecover`.
pub(crate) type Secp256k1PublicKey = [u8; SECP256K1_PUBLIC_KEY_LEN];

/// A duration or timestamp expressed in whole seconds. Serializes as `u64`.
pub type Seconds = u64;

/// A single decoded Feed Data package: the caller-facing result of a
/// successful feed lookup (price + aggregation timestamp).
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedData {
    /// Price value (10 bytes, big-endian) carried in a u128.
    pub price: U128,
    /// Aggregation timestamp in seconds (6 bytes, big-endian).
    pub timestamp: Seconds,
}

impl FeedData {
    /// Whether `timestamp` lies within `[now - max_delay, now + max_future_drift]`
    /// (all seconds). Bounds are added (not subtracted) and use `saturating_add`
    /// to avoid under/overflow; extreme bounds simply widen the window.
    pub(crate) fn is_timely(
        &self,
        now: Seconds,
        max_delay: Seconds,
        max_future_drift: Seconds,
    ) -> bool {
        self.timestamp.saturating_add(max_delay) >= now
            && self.timestamp <= now.saturating_add(max_future_drift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hex::encode as hex_encode;

    fn feed_at(timestamp: Seconds) -> FeedData {
        FeedData {
            price: U128(0),
            timestamp,
        }
    }

    mod parse_evm_address {
        use super::*;

        #[test]
        fn valid() {
            let addr = parse_evm_address(&format!("0x{}", hex_encode([0xABu8; EVM_ADDRESS_LEN])));
            assert_eq!(addr, [0xABu8; EVM_ADDRESS_LEN]);
        }

        #[test]
        fn accepts_mixed_case() {
            let addr = parse_evm_address("0xAbCdEf0123456789aBcDeF0123456789AbCdEf01");
            assert_eq!(
                addr,
                [
                    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
                    0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
                ]
            );
        }

        #[test]
        #[should_panic(expected = "Signer address must be 20 bytes")]
        fn too_long_panics() {
            let _ = parse_evm_address(&format!("0x{}", hex_encode([0u8; EVM_ADDRESS_LEN + 1])));
        }

        #[test]
        #[should_panic(expected = "Signer address must be 20 bytes")]
        fn too_short_panics() {
            let _ = parse_evm_address(&format!("0x{}", hex_encode([0u8; EVM_ADDRESS_LEN - 1])));
        }

        #[test]
        #[should_panic(expected = "Signer address must be 20 bytes")]
        fn empty_body_panics() {
            let _ = parse_evm_address("0x");
        }
    }

    mod is_timely {
        use super::*;

        #[test]
        fn accepts_within_window() {
            // now = 1000, window [1000-50, 1000+10] = [950, 1010].
            assert!(feed_at(1000).is_timely(1000, 50, 10)); // exactly now
            assert!(feed_at(950).is_timely(1000, 50, 10)); // oldest allowed
            assert!(feed_at(1010).is_timely(1000, 50, 10)); // furthest ahead allowed
        }

        #[test]
        fn rejects_too_old() {
            assert!(!feed_at(949).is_timely(1000, 50, 10));
        }

        #[test]
        fn rejects_too_future() {
            assert!(!feed_at(1011).is_timely(1000, 50, 10));
        }

        #[test]
        fn saturates_on_huge_delay() {
            // max_delay = u64::MAX would overflow with plain `+`; saturating_add caps it.
            assert!(feed_at(1000).is_timely(1000, u64::MAX, 10));
        }

        #[test]
        fn saturates_on_huge_future_drift() {
            assert!(feed_at(1000).is_timely(1000, 50, u64::MAX));
        }
    }
}
