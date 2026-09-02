//! Payload parsing & signature verification.
//!
//! This module owns everything about turning the raw signed payload bytes into
//! decoded `FeedData` values: the binary layout constants, the tail-based
//! framing, keccak256 + ecrecover signature verification, and big-endian field
//! decoding.
//!
//! Payload layout (bytes), parsed from the tail:
//!
//! ```text
//! [ Feed Data Packages : N * 20 ][ Count(N) : 1 ][ Signature : 65 ][ Magic Marker : 2 ]
//! ```
//!
//! Each package (20 bytes, big-endian): [ Feed ID : 4 ][ Value : 10 ][ Timestamp : 6 ]
//!
//! Signed data = Packages || Count; the Signature (r||s||v, Ethereum v 27/28)
//! and Magic Marker are not part of the signed data.

use near_sdk::{env, require};

use crate::hex::from_hex;
use crate::types::{EVM_ADDRESS_LEN, EvmAddress, FeedData, Secp256k1PublicKey};

/// Feed ID width within a package (bytes).
pub(crate) const FEED_ID_LEN: usize = 4;

/// Value width within a package (bytes).
pub(crate) const VALUE_LEN: usize = 10;

/// Timestamp width within a package (bytes).
pub(crate) const TIMESTAMP_LEN: usize = 6;

/// Size of a single Feed Data package in bytes.
pub(crate) const PACKAGE_LEN: usize = FEED_ID_LEN + VALUE_LEN + TIMESTAMP_LEN; // 20

/// Feed Data Count width (bytes).
pub(crate) const COUNT_LEN: usize = 1;

/// Signature width: r(32) + s(32) + v(1).
pub(crate) const SIGNATURE_LEN: usize = 65;

/// Length of the r||s portion of a signature (the signature without its v byte).
const RS_LEN: usize = SIGNATURE_LEN - 1;

/// Magic Marker width (bytes).
pub(crate) const MAGIC_LEN: usize = 2;

/// Tail metadata length: Count + Signature + Magic Marker.
pub(crate) const META_TAIL_LEN: usize = COUNT_LEN + SIGNATURE_LEN + MAGIC_LEN; // 68

/// Minimum valid payload length: at least one Feed Data package plus the
/// tail metadata. Empty (zero-feed) payloads are rejected.
pub(crate) const MIN_PAYLOAD_LEN: usize = META_TAIL_LEN + PACKAGE_LEN; // 88

/// Expected Magic Marker: the first two bytes of `keccak256("ATLAS")` = 0x7096,
/// stored big-endian as the tail 2 bytes of the payload.
pub(crate) const MAGIC_MARKER: [u8; MAGIC_LEN] = [0x70, 0x96];

/// A raw feed id: the 4-byte big-endian identifier.
pub(crate) type FeedId = [u8; FEED_ID_LEN];

/// Parse a `0x`-prefixed bytes4 hex string into the 4 raw feed-id bytes.
pub(crate) fn parse_feed_id(hex_str: &str) -> FeedId {
    let bytes = from_hex(hex_str);
    require!(bytes.len() == FEED_ID_LEN, "Feed id must be 4 bytes");
    let mut out = [0u8; FEED_ID_LEN];
    out.copy_from_slice(&bytes);
    out
}

/// Validate the payload framing and return the index where the Feed Data
/// packages region ends.
pub(crate) fn parse_metadata(payload: &[u8], max_package_count: u8) -> usize {
    let len = payload.len();

    // Require at least one package plus the tail metadata.
    require!(len >= MIN_PAYLOAD_LEN, "Payload too short");

    // Match the magic marker in the tail 2 bytes.
    require!(
        &payload[len - MAGIC_LEN..] == MAGIC_MARKER,
        "Invalid magic marker"
    );

    // Locate the packages end (= Count byte position), just before the tail metadata.
    let packages_end = len - META_TAIL_LEN;

    // Read the package count and reject zero.
    let count = payload[packages_end];
    require!(count != 0, "Feed Data Count is zero");

    // Enforce the upper bound on the package count, reporting both values.
    require!(
        count <= max_package_count,
        format!("Feed Data Count {count} exceeds maximum {max_package_count}")
    );

    // Check the total length equals count packages plus the tail metadata.
    require!(
        len == count as usize * PACKAGE_LEN + META_TAIL_LEN,
        "Payload length does not match count"
    );

    packages_end
}

/// Recover the signer's EVM address from the payload signature.
///
/// The address is NOT checked against the authorized signers here.
///
/// # Arguments
/// * `payload` - the full signed payload bytes
/// * `packages_end` - the Count byte position (where the packages region ends);
///   must come from a prior `parse_metadata` call on the same `payload`
///
/// # Panics
/// Panics on an invalid recovery id, or an invalid / non-canonical (high-s)
/// signature. EIP-2 low-s is enforced.
pub(crate) fn recover_signer(payload: &[u8], packages_end: usize) -> EvmAddress {
    let sig_start = packages_end + COUNT_LEN;

    // Slice the 65-byte signature (r||s||v) that follows the Count byte.
    let signature = &payload[sig_start..sig_start + SIGNATURE_LEN];

    // Derive the EVM address from the recovered public key.
    pubkey_to_evm_address(
        &env::ecrecover(
            // Digest the signed data: keccak256(Packages || Count).
            &env::keccak256_array(&payload[..sig_start]),
            // Take r||s; the slice is always RS_LEN bytes here, so this cannot fail.
            signature[..RS_LEN].try_into().unwrap(),
            // Normalize v to the {0, 1} recovery id ecrecover expects.
            normalize_v(signature[RS_LEN]),
            // Enforce EIP-2 low-s: reject non-canonical (high-s) signatures.
            true,
        )
        .expect("Invalid or non-canonical signature"),
    )
}

/// Find the feed whose id matches `feed_id`, scanning packages left to right and
/// stopping at the first match.
///
/// # Arguments
/// * `payload` - the full signed payload bytes
/// * `packages_end` - end index of the packages region; must come from a prior
///   `parse_metadata` call on the same `payload`, so the region is an exact
///   multiple of `PACKAGE_LEN`
/// * `feed_id` - the raw 4-byte id; only this prefix is compared per
///   package, so non-matching packages are not fully decoded
///
/// # Returns
/// `Some(FeedData)` for the first matching package, or `None` if no package
/// matches `feed_id`.
pub(crate) fn find_feed(payload: &[u8], packages_end: usize, feed_id: &FeedId) -> Option<FeedData> {
    let mut offset = 0;
    while offset < packages_end {
        if &payload[offset..offset + FEED_ID_LEN] == feed_id {
            return Some(decode_package(&payload[offset..offset + PACKAGE_LEN]));
        }
        offset += PACKAGE_LEN;
    }
    None
}

/// Derive the 20-byte EVM address from a 64-byte uncompressed public key
/// (X||Y, no 0x04 prefix): `keccak256(pubkey)[12..]`.
pub(crate) fn pubkey_to_evm_address(pubkey: &Secp256k1PublicKey) -> EvmAddress {
    let hash = env::keccak256_array(pubkey);
    let mut addr = [0u8; EVM_ADDRESS_LEN];
    addr.copy_from_slice(&hash[hash.len() - EVM_ADDRESS_LEN..]);
    addr
}

/// Decode a single 20-byte package's price and timestamp (big-endian). The feed
/// id prefix is matched by the caller and not decoded here.
fn decode_package(chunk: &[u8]) -> FeedData {
    // chunk is exactly PACKAGE_LEN: find_feed slices it by PACKAGE_LEN.
    let value = be_bytes_to_u128(&chunk[FEED_ID_LEN..FEED_ID_LEN + VALUE_LEN]);
    let timestamp =
        be_bytes_to_u64(&chunk[FEED_ID_LEN + VALUE_LEN..FEED_ID_LEN + VALUE_LEN + TIMESTAMP_LEN]);
    FeedData {
        price: value,
        timestamp,
    }
}

/// Normalize the signature's recovery id `v` to the {0, 1} form `env::ecrecover`
/// expects. The backend signs with Ethereum-style v (27/28); any other
/// value is rejected.
#[inline]
fn normalize_v(v: u8) -> u8 {
    match v {
        // 27/28 -> 0/1 recovery id.
        27 | 28 => v - 27,
        _ => env::panic_str("Invalid recovery id"),
    }
}

/// Big-endian bytes (<= 8) into u64.
fn be_bytes_to_u64(b: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    for &byte in b {
        acc = (acc << 8) | byte as u64;
    }
    acc
}

/// Big-endian bytes (<= 16) into u128.
fn be_bytes_to_u128(b: &[u8]) -> u128 {
    let mut acc: u128 = 0;
    for &byte in b {
        acc = (acc << 8) | byte as u128;
    }
    acc
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // alloy: Ethereum-style signing + address derivation (v = 27/28 built in).
    use alloy::primitives::keccak256;
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;
    use k256::ecdsa::Signature;

    const MAX_PACKAGE_COUNT: u8 = 32;

    pub fn expected_address(signer: &PrivateKeySigner) -> EvmAddress {
        signer.address().into_array()
    }

    /// Sign keccak256(raw_data) -> 65-byte r||s||v (Ethereum-style v 27/28).
    pub fn sign_eth(signer: &PrivateKeySigner, raw_data: &[u8]) -> [u8; SIGNATURE_LEN] {
        let digest = keccak256(raw_data); // alloy keccak256 -> B256
        let sig = signer.sign_hash_sync(&digest).expect("sign");
        sig.as_bytes()
    }

    /// Build a 20-byte package (big-endian): [feed_id:4][value:10][timestamp:6].
    pub fn package(feed_id: u32, value: u128, timestamp: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(PACKAGE_LEN);
        p.extend_from_slice(&feed_id.to_be_bytes());
        p.extend_from_slice(&value.to_be_bytes()[16 - VALUE_LEN..]);
        p.extend_from_slice(&timestamp.to_be_bytes()[8 - TIMESTAMP_LEN..]);
        p
    }

    /// Assemble a full payload: [packages][count][sig(65)][magic(2)].
    pub fn build_payload(signer: &PrivateKeySigner, feeds: &[(u32, u128, u64)]) -> Vec<u8> {
        let mut raw_data = Vec::new();
        for (id, v, t) in feeds {
            raw_data.extend_from_slice(&package(*id, *v, *t));
        }
        raw_data.push(feeds.len() as u8); // Packages || Count

        let sig = sign_eth(signer, &raw_data);

        let mut payload = raw_data;
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&MAGIC_MARKER);
        payload
    }

    pub fn fixed_key() -> PrivateKeySigner {
        // Deterministic non-zero key for reproducible tests.
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .expect("valid signing key")
    }

    mod parse_metadata {
        use super::*;

        #[test]
        fn valid_returns_packages_end() {
            let sk = fixed_key();
            let payload = build_payload(&sk, &[(1u32, 10u128, 5u64), (2u32, 20u128, 6u64)]);
            // 2 packages -> packages_end = 2 * PACKAGE_LEN.
            assert_eq!(parse_metadata(&payload, MAX_PACKAGE_COUNT), 2 * PACKAGE_LEN);
        }

        #[test]
        fn count_equal_to_max_accepted() {
            let sk = fixed_key();
            let feeds: Vec<_> = (0..MAX_PACKAGE_COUNT as u32)
                .map(|i| (i, 1u128, 1u64))
                .collect();
            let payload = build_payload(&sk, &feeds);
            assert_eq!(
                parse_metadata(&payload, MAX_PACKAGE_COUNT),
                MAX_PACKAGE_COUNT as usize * PACKAGE_LEN
            );
        }

        #[test]
        #[should_panic(expected = "Payload too short")]
        fn too_short_rejected() {
            // Below MIN_PAYLOAD_LEN (< 88 bytes).
            let _ = parse_metadata(&[0u8; MIN_PAYLOAD_LEN - 1], MAX_PACKAGE_COUNT);
        }

        #[test]
        #[should_panic(expected = "Invalid magic marker")]
        fn bad_magic_rejected() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            let n = payload.len();
            payload[n - 1] ^= 0xFF;
            let _ = parse_metadata(&payload, MAX_PACKAGE_COUNT);
        }

        #[test]
        #[should_panic(expected = "Feed Data Count is zero")]
        fn zero_count_with_package_rejected() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            let count_pos = payload.len() - META_TAIL_LEN;
            payload[count_pos] = 0;
            let _ = parse_metadata(&payload, MAX_PACKAGE_COUNT);
        }

        #[test]
        #[should_panic(expected = "Feed Data Count 33 exceeds maximum 32")]
        fn count_exceeds_max_rejected() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            let count_pos = payload.len() - META_TAIL_LEN;
            payload[count_pos] = MAX_PACKAGE_COUNT + 1;
            let _ = parse_metadata(&payload, MAX_PACKAGE_COUNT);
        }

        #[test]
        #[should_panic(expected = "Payload length does not match count")]
        fn length_mismatch_rejected() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 10u128, 5u64), (2u32, 20u128, 6u64)]);
            let count_pos = payload.len() - META_TAIL_LEN;
            payload[count_pos] = 1; // claim 1 package while 2 are present
            let _ = parse_metadata(&payload, MAX_PACKAGE_COUNT);
        }
    }

    mod normalize_v {
        use super::*;

        #[test]
        fn maps_eth_style() {
            // Ethereum-style ids (as produced by the web3j backend) map to {0, 1}.
            assert_eq!(normalize_v(27), 0);
            assert_eq!(normalize_v(28), 1);
        }

        #[test]
        #[should_panic(expected = "Invalid recovery id")]
        fn rejects_non_eth_style() {
            // Any v outside {27, 28} is rejected (raw 0/1, EIP-155 tx v, junk, ...).
            let _ = normalize_v(1);
        }
    }

    mod be_bytes {
        use super::*;

        #[test]
        fn u64_decodes_big_endian() {
            assert_eq!(be_bytes_to_u64(&[]), 0); // empty -> 0
            assert_eq!(be_bytes_to_u64(&[0x00, 0x12]), 0x12); // leading zero
            assert_eq!(be_bytes_to_u64(&[0x01, 0x00]), 256); // ordering
            assert_eq!(be_bytes_to_u64(&[0xFF; 6]), 0xFFFF_FFFF_FFFF); // 6-byte full
        }

        #[test]
        fn u128_decodes_big_endian() {
            assert_eq!(be_bytes_to_u128(&[]), 0);
            assert_eq!(be_bytes_to_u128(&[0x01, 0x00]), 256);
            // 10-byte value field, all 0xFF -> 2^80 - 1.
            assert_eq!(be_bytes_to_u128(&[0xFF; 10]), (1u128 << 80) - 1);
        }
    }

    mod decode_package {
        use super::*;

        #[test]
        fn extracts_fields() {
            // feed_id (first FEED_ID_LEN bytes) is ignored by decode_package.
            // value occupies the next VALUE_LEN bytes, timestamp the last TIMESTAMP_LEN.
            let mut chunk = vec![0u8; PACKAGE_LEN];
            chunk[FEED_ID_LEN + VALUE_LEN - 1] = 42; // value low byte -> 42
            chunk[PACKAGE_LEN - 1] = 5; // timestamp low byte -> 5

            let feed = decode_package(&chunk);
            assert_eq!(feed.price, 42);
            assert_eq!(feed.timestamp, 5);
        }

        #[test]
        fn decodes_multibyte_big_endian() {
            // Verify big-endian ordering across multiple bytes, not just the low byte.
            let mut chunk = vec![0u8; PACKAGE_LEN];
            // value = 0x0100 = 256 (high byte set one position up from the low byte).
            chunk[FEED_ID_LEN + VALUE_LEN - 2] = 0x01;
            // timestamp = 0x0100 = 256.
            chunk[PACKAGE_LEN - 2] = 0x01;

            let feed = decode_package(&chunk);
            assert_eq!(feed.price, 256);
            assert_eq!(feed.timestamp, 256);
        }
    }

    mod pubkey_to_evm_address {
        use super::*;

        #[test]
        fn derives_address_from_pubkey() {
            // Derive from a fixed key: pubkey_to_evm_address must match alloy's
            // address() (both compute keccak256(pubkey)[12..]).
            let signer = fixed_key();
            let verifying = signer.credential().verifying_key(); // k256 VerifyingKey
            let point = verifying.to_encoded_point(false); // 65 bytes: 0x04 || X || Y
            let pubkey: Secp256k1PublicKey = point.as_bytes()[1..].try_into().unwrap();

            assert_eq!(pubkey_to_evm_address(&pubkey), expected_address(&signer));
        }
    }

    mod find_feed {
        use super::*;

        #[test]
        fn selects_matching_package() {
            let sk = fixed_key();
            let feeds = [
                (10u32, 100u128, 1u64),
                (20u32, 200u128, 2u64),
                (30u32, 300u128, 3u64),
            ];
            let payload = build_payload(&sk, &feeds);
            let packages_end = parse_metadata(&payload, MAX_PACKAGE_COUNT);

            // A middle package is found and decoded.
            let f = find_feed(&payload, packages_end, &20u32.to_be_bytes()).unwrap();
            assert_eq!(f.price, 200);
            assert_eq!(f.timestamp, 2);

            // First and last also resolve to their own data.
            let first = find_feed(&payload, packages_end, &10u32.to_be_bytes()).unwrap();
            assert_eq!(first.price, 100);
            assert_eq!(first.timestamp, 1);

            let last = find_feed(&payload, packages_end, &30u32.to_be_bytes()).unwrap();
            assert_eq!(last.price, 300);
            assert_eq!(last.timestamp, 3);
        }

        #[test]
        fn absent_returns_none() {
            let sk = fixed_key();
            let payload = build_payload(&sk, &[(10u32, 100u128, 1u64)]);
            let packages_end = parse_metadata(&payload, MAX_PACKAGE_COUNT);
            assert!(find_feed(&payload, packages_end, &999u32.to_be_bytes()).is_none());
        }

        #[test]
        fn duplicate_id_returns_first_match() {
            let sk = fixed_key();
            // Two packages share feed id 7; find_feed must return the FIRST one
            // (price 100), not the later duplicate (price 200).
            let payload = build_payload(&sk, &[(7u32, 100u128, 1u64), (7u32, 200u128, 2u64)]);
            let packages_end = parse_metadata(&payload, MAX_PACKAGE_COUNT);

            let f = find_feed(&payload, packages_end, &7u32.to_be_bytes()).unwrap();
            assert_eq!(f.price, 100); // first match wins
            assert_eq!(f.timestamp, 1);
        }
    }

    mod parse_feed_id {
        use super::*;

        #[test]
        fn valid() {
            assert_eq!(parse_feed_id("0x00000001"), [0, 0, 0, 1]);
        }

        #[test]
        #[should_panic(expected = "Feed id must be 4 bytes")]
        fn too_short_panics() {
            // 3 bytes (6 hex chars) is rejected.
            let _ = parse_feed_id("0x000001");
        }

        #[test]
        #[should_panic(expected = "Feed id must be 4 bytes")]
        fn too_long_panics() {
            // 5 bytes (10 hex chars) is rejected.
            let _ = parse_feed_id("0x0000000001");
        }

        #[test]
        #[should_panic(expected = "Feed id must be 4 bytes")]
        fn empty_body_panics() {
            // "0x" decodes to empty -> length 0 != FEED_ID_LEN.
            let _ = parse_feed_id("0x");
        }
    }

    mod recover_signer {
        use super::*;

        /// Rewrite the signature's `v` byte in place (last byte of the 65-byte sig,
        /// which sits just before the 2-byte magic marker).
        fn set_v(payload: &mut [u8], v: u8) {
            let n = payload.len();
            payload[n - MAGIC_LEN - 1] = v;
        }

        #[test]
        fn matches_address() {
            let sk = fixed_key();
            let payload = build_payload(&sk, &[(1u32, 123_456u128, 1_700_000_000u64)]);
            assert_eq!(
                recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT)),
                expected_address(&sk)
            );
        }

        #[test]
        #[should_panic(expected = "Payload too short")]
        fn zero_feeds_rejected() {
            let sk = fixed_key();
            // A zero-feed payload is below MIN_PAYLOAD_LEN and must be rejected.
            let payload = build_payload(&sk, &[]);
            let _ = recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT));
        }

        #[test]
        fn tampered_yields_different_address() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            // Tamper a value byte inside the first package (same length).
            payload[10] ^= 0x01;
            // recover_signer does NOT check the authorized signers; it just recovers
            // whatever address the (now different) signature maps to — not ours.
            assert_ne!(
                recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT)),
                expected_address(&sk)
            );
        }

        #[test]
        #[should_panic(expected = "Invalid magic marker")]
        fn bad_magic_panics() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            let n = payload.len();
            payload[n - 1] ^= 0xFF;
            let _ = recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT));
        }

        #[test]
        #[should_panic(expected = "Invalid recovery id")]
        fn bad_v_panics() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            set_v(&mut payload, 42);
            let _ = recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT));
        }

        #[test]
        #[should_panic(expected = "Invalid or non-canonical signature")]
        fn high_s_rejected_by_eip2() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);

            // Flip the (low-s) signature to its equivalent non-canonical high-s form
            // (s -> n - s) and flip v's parity. The result is mathematically valid
            // but must be rejected under EIP-2 with malleability_flag = true.
            let sig_start = payload.len() - MAGIC_LEN - SIGNATURE_LEN;
            let sig = Signature::try_from(&payload[sig_start..sig_start + 64]).unwrap();
            let high_sig =
                Signature::from_scalars(*sig.r().as_ref(), *(-sig.s()).as_ref()).unwrap();
            payload[sig_start..sig_start + 64].copy_from_slice(&high_sig.to_bytes());

            // Flip v parity (the eth-style byte alternates 27 <-> 28).
            let v = payload[payload.len() - MAGIC_LEN - 1];
            set_v(&mut payload, if v == 27 { 28 } else { 27 });

            let _ = recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT));
        }

        #[test]
        #[should_panic(expected = "Invalid or non-canonical signature")]
        fn garbage_signature_fails() {
            let sk = fixed_key();
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 5u64)]);
            // Zero out r and s: an all-zero (r, s) is not a recoverable signature.
            let sig_start = payload.len() - MAGIC_LEN - SIGNATURE_LEN;
            for b in &mut payload[sig_start..sig_start + 64] {
                *b = 0;
            }
            let _ = recover_signer(&payload, parse_metadata(&payload, MAX_PACKAGE_COUNT));
        }
    }
}
