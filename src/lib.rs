//! Pull Oracle Verifier contract for NEAR.
//!
//! A stateless (view-based) verifier holding an owner plus a set of authorized
//! oracle signer EVM addresses. Callers pass a backend-signed price payload to
//! `get_verified_feed_data`, which recovers the signer's EVM address from the
//! ECDSA signature, checks it is authorized, then returns the requested feed.
//!
//! Payload layout and signature scheme are documented in the `payload` module.
mod events;
mod hex;
mod payload;
mod types;

use near_sdk::{
    AccountId, BorshStorageKey, PanicOnDefault, assert_one_yocto, env, near, require,
    store::LookupSet,
};

use crate::{
    hex::from_hex,
    payload::parse_feed_id,
    types::{EvmAddress, Seconds, parse_evm_address},
};
use events::ContractEvent;
pub use types::FeedData;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    AuthorizedSigners,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PullVerifier {
    /// Account allowed to manage authorized signers.
    owner: AccountId,
    /// Authorized oracle signer EVM addresses.
    authorized_signers: LookupSet<EvmAddress>,
}

#[near]
impl PullVerifier {
    /// Initialize the verifier.
    ///
    /// # Arguments
    /// * `owner` - account allowed to manage signers and transfer ownership.
    /// * `initial_signers` - authorized signer EVM addresses, each a
    ///   `0x`-prefixed 40-hex-char string. May be empty, in which case no signer
    ///   is authorized until `set_signer` adds one.
    #[init]
    pub fn new(owner: AccountId, initial_signers: Vec<String>) -> Self {
        let mut authorized_signers = LookupSet::new(StorageKey::AuthorizedSigners);
        for s in &initial_signers {
            authorized_signers.insert(parse_evm_address(s));
            ContractEvent::SignerStatusChanged {
                signer: s.clone(),
                added: true,
            }
            .emit();
        }

        ContractEvent::OwnershipTransferred {
            old_owner: None,
            new_owner: owner.clone(),
        }
        .emit();

        Self {
            owner,
            authorized_signers,
        }
    }

    /// Add or remove an authorized signer address. Owner-only.
    ///
    /// # Arguments
    /// * `evm_address_hex` - the signer EVM address, a `0x`-prefixed 40-hex-char
    ///   string (the `0x` prefix is required).
    /// * `add` - `true` to add, `false` to remove.
    #[payable]
    pub fn set_signer(&mut self, evm_address_hex: String, add: bool) {
        assert_one_yocto();
        require!(
            env::predecessor_account_id() == self.owner,
            "Only the owner can set the signer"
        );
        let address = parse_evm_address(&evm_address_hex);

        let changed = if add {
            self.authorized_signers.insert(address)
        } else {
            self.authorized_signers.remove(&address)
        };
        require!(changed, "Signer already in the requested state");

        ContractEvent::SignerStatusChanged {
            signer: evm_address_hex,
            added: add,
        }
        .emit();
    }

    /// Whether the given EVM address is an authorized signer.
    ///
    /// # Arguments
    /// * `evm_address_hex` - a `0x`-prefixed 40-hex-char EVM address.
    pub fn is_signer(&self, evm_address_hex: String) -> bool {
        self.authorized_signers
            .contains(&parse_evm_address(&evm_address_hex))
    }

    /// Current owner account.
    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    /// Transfer ownership to `new_owner`. Owner-only.
    ///
    /// Takes effect immediately. Double-check `new_owner`: transferring to a
    /// wrong or uncontrolled account permanently loses management access.
    ///
    /// # Arguments
    /// * `new_owner` - the account to become the new owner.
    #[payable]
    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        assert_one_yocto();
        require!(
            env::predecessor_account_id() == self.owner,
            "Only the owner can transfer ownership"
        );
        require!(
            new_owner != self.owner,
            "New owner must differ from the current owner"
        );

        let old_owner = self.owner.clone();
        self.owner = new_owner.clone();

        ContractEvent::OwnershipTransferred {
            old_owner: Some(old_owner),
            new_owner,
        }
        .emit();
    }

    /// Return the feed matching `feed_id`, verifying the payload and the feed's
    /// freshness.
    ///
    /// The feed's timestamp must lie within `[now - max_delay, now +
    /// max_future_drift]` (block time, seconds).
    ///
    /// # Arguments
    /// * `feed_id` - a `0x`-prefixed 8-hex-char string (EVM `bytes4`)
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages in the payload
    /// * `max_delay` - max staleness: how far in the past the timestamp may be
    /// * `max_future_drift` - max clock skew: how far ahead the timestamp may be
    ///
    /// # Panics
    /// Panics on an untrusted payload (bad framing, invalid/non-canonical
    /// signature, or unauthorized signer) or a malformed `feed_id`.
    ///
    /// # Returns
    /// `Some(feed)` if present and fresh; `None` if the feed is absent or its
    /// timestamp is out of range (so callers can fall back or skip).
    pub fn get_verified_feed_data(
        &self,
        feed_id: String,
        payload: String,
        max_package_count: u8,
        max_delay: Seconds,
        max_future_drift: Seconds,
    ) -> Option<FeedData> {
        let feed = self.find_authenticated_feed(&feed_id, &payload, max_package_count)?;
        let now: Seconds = env::block_timestamp() / 1_000_000_000; // ns -> s
        feed.is_timely(now, max_delay, max_future_drift)
            .then_some(feed)
    }

    /// Batch [`PullVerifier::get_verified_feed_data`]: authenticate the payload once,
    /// then look up each id in `feed_ids`.
    ///
    /// # Arguments
    /// * `feed_ids` - `0x`-prefixed 8-hex-char (EVM `bytes4`) ids to look up
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages in the payload
    /// * `max_delay` - max staleness: how far in the past a timestamp may be
    /// * `max_future_drift` - max clock skew: how far ahead a timestamp may be
    ///
    /// # Panics
    /// Panics (failing the whole call) on an untrusted payload or any malformed
    /// `feed_id`.
    ///
    /// # Returns
    /// One entry per input id, index-aligned: `Some(feed)` if present and fresh,
    /// else `None` when that feed is absent or its timestamp is out of range.
    /// An empty `feed_ids` yields an empty vector.
    pub fn get_verified_feed_data_batch(
        &self,
        feed_ids: Vec<String>,
        payload: String,
        max_package_count: u8,
        max_delay: Seconds,
        max_future_drift: Seconds,
    ) -> Vec<Option<FeedData>> {
        self.find_authenticated_feeds(
            &feed_ids,
            &payload,
            max_package_count,
            Some((max_delay, max_future_drift)),
        )
    }

    /// Return the feed matching `feed_id` WITHOUT any freshness check.
    ///
    /// The payload is still fully authenticated (signature + authorized signer),
    /// so the data's origin is trusted — but its timestamp is NOT validated, so
    /// it may be stale. Prefer [`PullVerifier::get_verified_feed_data`] unless you
    /// need to apply your own freshness policy.
    ///
    /// # Arguments
    /// * `feed_id` - a `0x`-prefixed 8-hex-char string (EVM `bytes4`)
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages in the payload
    ///
    /// # Panics
    /// Panics on an untrusted payload or a malformed `feed_id`.
    ///
    /// # Returns
    /// `Some(feed)` if present (possibly stale — callers MUST inspect
    /// `FeedData::timestamp`), or `None` if the feed is absent.
    pub fn get_feed_data_unchecked(
        &self,
        feed_id: String,
        payload: String,
        max_package_count: u8,
    ) -> Option<FeedData> {
        self.find_authenticated_feed(&feed_id, &payload, max_package_count)
    }

    /// Batch [`PullVerifier::get_feed_data_unchecked`]: authenticate the payload once,
    /// then look up each id in `feed_ids` WITHOUT a freshness check.
    ///
    /// # Arguments
    /// * `feed_ids` - `0x`-prefixed 8-hex-char (EVM `bytes4`) ids to look up
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages in the payload
    ///
    /// # Panics
    /// Panics on an untrusted payload or any malformed `feed_id`.
    ///
    /// # Returns
    /// One entry per input id, index-aligned: `Some(feed)` if present, else
    /// `None`. Feeds may be stale — callers MUST inspect each
    /// `FeedData::timestamp`. An empty `feed_ids` yields an empty vector.
    pub fn get_feed_data_unchecked_batch(
        &self,
        feed_ids: Vec<String>,
        payload: String,
        max_package_count: u8,
    ) -> Vec<Option<FeedData>> {
        self.find_authenticated_feeds(&feed_ids, &payload, max_package_count, None)
    }

    /// Authenticate a raw payload and return where the packages region ends.
    ///
    /// Validates the framing, recovers the signer's EVM address, and requires it
    /// to be authorized.
    fn authenticate(&self, payload: &[u8], max_package_count: u8) -> usize {
        let packages_end = payload::parse_metadata(payload, max_package_count);
        let signer = payload::recover_signer(payload, packages_end);
        require!(
            self.authorized_signers.contains(&signer),
            "Signer address is not authorized"
        );
        packages_end
    }

    /// Authenticate the payload, then return the feed matching `feed_id`, or
    /// `None` if absent. No freshness check — shared by the verified and
    /// unchecked single-feed lookups.
    fn find_authenticated_feed(
        &self,
        feed_id: &str,
        payload: &str,
        max_package_count: u8,
    ) -> Option<FeedData> {
        let payload: Vec<u8> = from_hex(payload);
        payload::find_feed(
            &payload,
            self.authenticate(&payload, max_package_count),
            &parse_feed_id(feed_id),
        )
    }

    /// Authenticate the payload once, then look up each id in `feed_ids`,
    /// index-aligned. `timeliness_bounds = Some((max_delay, max_future_drift))`
    /// drops out-of-range feeds to `None`; `None` skips the freshness check.
    /// An empty `feed_ids` returns early without authenticating. Shared by the
    /// verified and unchecked batch lookups.
    fn find_authenticated_feeds(
        &self,
        feed_ids: &[String],
        payload: &str,
        max_package_count: u8,
        timeliness_bounds: Option<(Seconds, Seconds)>,
    ) -> Vec<Option<FeedData>> {
        if feed_ids.is_empty() {
            return Vec::new();
        }

        let payload: Vec<u8> = from_hex(payload);
        let now: Seconds = env::block_timestamp() / 1_000_000_000; // ns -> s
        let packages_end = self.authenticate(&payload, max_package_count);

        feed_ids
            .iter()
            .map(|feed_id| {
                let feed = payload::find_feed(&payload, packages_end, &parse_feed_id(feed_id));
                match timeliness_bounds {
                    Some((max_delay, max_future_drift)) => {
                        feed.filter(|f| f.is_timely(now, max_delay, max_future_drift))
                    }
                    None => feed,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::tests::{build_payload, expected_address, fixed_key};
    use crate::types::EVM_ADDRESS_LEN;
    use ::hex::encode as hex_encode;
    use alloy::signers::local::PrivateKeySigner;
    use near_sdk::{
        json_types::U128,
        test_utils::{VMContextBuilder, accounts, get_logs},
        testing_env,
    };
    use payload::{META_TAIL_LEN, MIN_PAYLOAD_LEN};

    const MAX_PACKAGE_COUNT: u8 = 32;

    // Feed ids as 0x-prefixed bytes4 hex (feed_id 1 and 999).
    const FEED_1: &str = "0x00000001";
    const FEED_999: &str = "0x000003e7";

    /// Context with the block time set to `now_sec` (seconds).
    fn set_ctx_at(now_sec: u64) {
        let ctx = VMContextBuilder::new()
            .predecessor_account_id(accounts(1))
            .block_timestamp(now_sec * 1_000_000_000)
            .build();
        testing_env!(ctx);
    }

    /// A second signer built from a fixed byte, for multi-signer tests.
    fn key_from_byte(b: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&[b; 32]).expect("valid signing key")
    }

    /// Encode raw payload bytes as the `0x`-prefixed hex string `verify` expects.
    fn hex_payload(bytes: &[u8]) -> String {
        format!("0x{}", hex_encode(bytes))
    }

    /// The signer's EVM address as a `0x`-prefixed hex string (what the
    /// contract API expects).
    fn address_of(signer: &PrivateKeySigner) -> String {
        format!("0x{}", hex_encode(expected_address(signer)))
    }

    fn contract_for(signer: &PrivateKeySigner) -> PullVerifier {
        PullVerifier::new(accounts(0), vec![address_of(&signer)])
    }

    fn set_ctx_as_with_1_yocto(who: AccountId) {
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(who)
                .attached_deposit(near_sdk::NearToken::from_yoctonear(1))
                .build()
        );
    }

    mod new {
        use super::*;

        #[test]
        fn stores_owner_and_authorized_signers() {
            let sk = fixed_key();
            let contract = PullVerifier::new(accounts(0), vec![address_of(&sk)]);

            assert_eq!(contract.get_owner(), accounts(0));
            assert!(contract.is_signer(address_of(&sk)));

            // Events: one SignerStatusChanged for the signer, plus the initial
            // OwnershipTransferred (old_owner = null).
            let logs = get_logs();
            assert_eq!(logs.len(), 2);
            assert!(logs[0].contains(r#""event":"signer_status_changed""#));
            assert!(logs[0].contains(r#""added":true"#));
            assert!(logs[0].contains(&address_of(&sk)));
            assert!(logs[1].contains(r#""event":"ownership_transferred""#));
            assert!(logs[1].contains(r#""old_owner":null"#));
            assert!(logs[1].contains(accounts(0).as_str()));
        }

        #[test]
        fn authorizes_multiple_signers() {
            let sk1 = fixed_key();
            let sk2 = key_from_byte(3);
            let contract = PullVerifier::new(accounts(0), vec![address_of(&sk1), address_of(&sk2)]);

            assert!(contract.is_signer(address_of(&sk1)));
            assert!(contract.is_signer(address_of(&sk2)));

            // Events: one SignerStatusChanged per signer (in order), plus the
            // initial OwnershipTransferred.
            let logs = get_logs();
            assert_eq!(logs.len(), 3);
            assert!(logs[0].contains(r#""event":"signer_status_changed""#));
            assert!(logs[0].contains(r#""added":true"#));
            assert!(logs[0].contains(&address_of(&sk1)));
            assert!(logs[1].contains(r#""event":"signer_status_changed""#));
            assert!(logs[1].contains(r#""added":true"#));
            assert!(logs[1].contains(&address_of(&sk2)));
            assert!(logs[2].contains(r#""event":"ownership_transferred""#));
            assert!(logs[2].contains(r#""old_owner":null"#));
            assert!(logs[2].contains(accounts(0).as_str()));
        }

        #[test]
        fn empty_signers_authorizes_none() {
            let contract = PullVerifier::new(accounts(0), vec![]);

            // No signer is authorized; a well-formed address still returns false.
            let sk = fixed_key();
            assert!(!contract.is_signer(address_of(&sk)));

            // Only one log: the initial OwnershipTransferred (no signer events).
            let logs = get_logs();
            assert_eq!(logs.len(), 1);
            assert!(logs[0].contains(r#""event":"ownership_transferred""#));
            assert!(logs[0].contains(r#""old_owner":null"#));
            assert!(logs[0].contains(accounts(0).as_str()));
        }

        #[test]
        #[should_panic(expected = "Signer address must be 20 bytes")]
        fn malformed_signer_address_panics() {
            // 19-byte address (38 hex chars) is rejected by parse_evm_address.
            let bad = format!("0x{}", hex_encode([0u8; EVM_ADDRESS_LEN - 1]));
            let _ = PullVerifier::new(accounts(0), vec![bad]);
        }
    }

    mod set_signer {
        use super::*;

        #[test]
        fn add_then_remove_by_owner() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);

            // Add a second signer (not yet authorized).
            let new_sk = key_from_byte(3);
            let new_addr = address_of(&new_sk);
            assert!(!contract.is_signer(new_addr.clone()));

            set_ctx_as_with_1_yocto(accounts(0));
            contract.set_signer(new_addr.clone(), true);
            assert!(contract.is_signer(new_addr.clone()));
            let mut logs = get_logs();
            assert_eq!(logs.len(), 1);
            assert!(logs[0].contains(r#""event":"signer_status_changed""#));
            assert!(logs[0].contains(r#""added":true"#));
            assert!(logs[0].contains(&new_addr));

            // Remove it again.
            set_ctx_as_with_1_yocto(accounts(0));
            contract.set_signer(new_addr.clone(), false);
            assert!(!contract.is_signer(new_addr.clone()));
            logs = get_logs();
            assert_eq!(logs.len(), 1);
            assert!(logs[0].contains(r#""event":"signer_status_changed""#));
            assert!(logs[0].contains(r#""added":false"#));
            assert!(logs[0].contains(&new_addr));
        }

        #[test]
        #[should_panic(expected = "Only the owner can set the signer")]
        fn by_non_owner_fails() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);

            set_ctx_as_with_1_yocto(accounts(2)); // not the owner (owner is accounts(0))
            contract.set_signer(address_of(&sk), true);
        }

        #[test]
        #[should_panic(expected = "Signer already in the requested state")]
        fn adding_already_authorized_signer_panics() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk); // sk is already authorized via new()

            // Re-adding an already-authorized signer is a no-op change -> revert.
            set_ctx_as_with_1_yocto(accounts(0));
            contract.set_signer(address_of(&sk), true);
        }

        #[test]
        #[should_panic(expected = "Signer already in the requested state")]
        fn removing_unauthorized_signer_panics() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);
            // Removing a never-authorized address is a no-op change -> revert.
            set_ctx_as_with_1_yocto(accounts(0));
            let other = key_from_byte(1);
            contract.set_signer(address_of(&other), false);
        }
    }

    mod transfer_ownership {
        use super::*;

        #[test]
        fn switches_authority_and_emits_event() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);

            set_ctx_as_with_1_yocto(accounts(0));
            contract.transfer_ownership(accounts(3));

            // Owner is updated.
            assert_eq!(contract.get_owner(), accounts(3));

            let logs = get_logs();
            assert_eq!(logs.len(), 1);
            assert!(logs[0].contains(r#""event":"ownership_transferred""#));
            assert!(logs[0].contains(accounts(0).as_str())); // old_owner
            assert!(logs[0].contains(accounts(3).as_str())); // new_owner
            assert!(!logs[0].contains(r#""old_owner":null"#));
        }

        #[test]
        fn new_owner_can_manage_signers() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);

            set_ctx_as_with_1_yocto(accounts(0));
            contract.transfer_ownership(accounts(3));

            // The new owner can now manage signers.
            set_ctx_as_with_1_yocto(accounts(3));
            let new_addr = format!("0x{}", hex_encode([2u8; EVM_ADDRESS_LEN]));
            contract.set_signer(new_addr.clone(), true);
            assert!(contract.is_signer(new_addr));
        }

        #[test]
        #[should_panic(expected = "Only the owner can transfer ownership")]
        fn by_non_owner_fails() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);
            set_ctx_as_with_1_yocto(accounts(2));
            contract.transfer_ownership(accounts(3));
        }

        #[test]
        #[should_panic(expected = "Only the owner can set the signer")]
        fn old_owner_cannot_manage_after_transfer() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);

            set_ctx_as_with_1_yocto(accounts(0));
            contract.transfer_ownership(accounts(3));

            // The old owner (accounts(0)) can no longer manage signers.
            contract.set_signer(format!("0x{}", hex_encode([2u8; EVM_ADDRESS_LEN])), true);
        }

        #[test]
        #[should_panic(expected = "New owner must differ from the current owner")]
        fn to_same_owner_fails() {
            let sk = fixed_key();
            let mut contract = contract_for(&sk);
            set_ctx_as_with_1_yocto(accounts(0));
            contract.transfer_ownership(accounts(0));
        }
    }

    mod get_feed_data_unchecked {
        use super::*;

        #[test]
        fn returns_stale_feed() {
            // Now is far past the feed timestamps; get_verified_feed_data would
            // reject them, but the unchecked variant returns regardless of age.
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Two packages in the payload; query the second one (feed id 2).
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            let feed = contract
                .get_feed_data_unchecked(
                    "0x00000002".into(),
                    hex_payload(&payload),
                    MAX_PACKAGE_COUNT,
                )
                .expect("present feed is returned regardless of age");
            assert_eq!(feed.price, U128(99));
            assert_eq!(feed.timestamp, 1_700_000_050);
        }

        #[test]
        fn missing_returns_none() {
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Two packages present, but query an id that is absent (999).
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            assert!(
                contract
                    .get_feed_data_unchecked(
                        FEED_999.into(),
                        hex_payload(&payload),
                        MAX_PACKAGE_COUNT
                    )
                    .is_none()
            );
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn untrusted_payload_panics() {
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            payload[10] ^= 0x01; // tamper -> recovers an unauthorized signer
            let _ = contract.get_feed_data_unchecked(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn wrong_signer_fails() {
            set_ctx_at(9_999_999_999);
            let signing = fixed_key();
            let other = key_from_byte(9); // contract authorizes a DIFFERENT signer
            let contract = contract_for(&other);

            let payload = build_payload(&signing, &[(1u32, 100u128, 1_700_000_000u64)]);
            let _ = contract.get_feed_data_unchecked(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Feed Data Count 2 exceeds maximum 1")]
        fn max_package_count_below_actual_panics() {
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Payload has 2 packages, but the caller caps max_package_count at 1.
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );

            let _ = contract.get_feed_data_unchecked(FEED_1.into(), hex_payload(&payload), 1);
        }

        #[test]
        #[should_panic(expected = "Invalid magic marker")]
        fn bad_magic_fails() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            let n = payload.len();
            payload[n - 1] ^= 0xFF;
            let _ = contract.get_feed_data_unchecked(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Payload too short")]
        fn too_short_fails() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let _ = contract.get_feed_data_unchecked(
                FEED_1.into(),
                hex_payload(&[0u8; 10]),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Payload length does not match count")]
        fn count_mismatch_fails() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            let count_pos = payload.len() - META_TAIL_LEN;
            payload[count_pos] = 5;
            let _ = contract.get_feed_data_unchecked(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Feed id must be 4 bytes")]
        fn bad_feed_id_len_panics() {
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            // 3-byte feed id (6 hex chars) is rejected.
            let _ = contract.get_feed_data_unchecked(
                "0x000001".into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }
    }

    mod get_feed_data_unchecked_batch {
        use super::*;

        #[test]
        fn index_aligned_and_stale() {
            // Now is far past the timestamps; entries are still returned (no
            // freshness check), and absent ids map to None, index-aligned.
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            // Query order: feed 2, absent 999, feed 1 -> results index-aligned.
            let out = contract.get_feed_data_unchecked_batch(
                vec!["0x00000002".into(), FEED_999.into(), FEED_1.into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );

            assert_eq!(out.len(), 3);
            // feed 2, stale but returned
            assert_eq!(out[0].as_ref().unwrap().price, U128(99));
            assert_eq!(out[0].as_ref().unwrap().timestamp, 1_700_000_050);
            // feed 999 absent
            assert!(out[1].is_none());
            // feed 1, stale but returned
            assert_eq!(out[2].as_ref().unwrap().price, U128(42));
            assert_eq!(out[2].as_ref().unwrap().timestamp, 1_700_000_000);
        }

        #[test]
        fn empty_ids_returns_empty() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let out = contract.get_feed_data_unchecked_batch(vec![], hex_payload(&Vec::new()), 0);
            assert!(out.is_empty());
        }

        #[test]
        fn duplicate_ids_each_resolve() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Two packages; query the SECOND one (feed id 2) twice.
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            // The same id queried twice yields the same feed at both positions.
            let out = contract.get_feed_data_unchecked_batch(
                vec!["0x00000002".into(), "0x00000002".into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );

            assert_eq!(out.len(), 2);

            let first = out[0].as_ref().unwrap();
            assert_eq!(first.price, U128(99));
            assert_eq!(first.timestamp, 1_700_000_050);

            let second = out[1].as_ref().unwrap();
            assert_eq!(second.price, U128(99));
            assert_eq!(second.timestamp, 1_700_000_050);
        }

        #[test]
        fn all_absent_returns_all_none() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            // Query two ids that are both absent from the payload.
            let out = contract.get_feed_data_unchecked_batch(
                vec![FEED_999.into(), "0x0000abcd".into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
            assert_eq!(out.len(), 2);
            assert!(out[0].is_none());
            assert!(out[1].is_none());
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn untrusted_payload_panics() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            payload[10] ^= 0x01; // tamper -> recovers an unauthorized signer
            let _ = contract.get_feed_data_unchecked_batch(
                vec![FEED_1.into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
            );
        }

        #[test]
        #[should_panic(expected = "Feed Data Count 2 exceeds maximum 1")]
        fn max_package_count_below_actual_panics() {
            set_ctx_at(9_999_999_999);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            // 2 packages but cap at 1 -> rejected by parse_metadata.
            let _ = contract.get_feed_data_unchecked_batch(
                vec![FEED_1.into()],
                hex_payload(&payload),
                1,
            );
        }
    }

    mod get_verified_feed_data {
        use super::*;

        #[test]
        fn returns_fresh_feed() {
            set_ctx_at(1_700_000_100); // 100s after the feed's timestamp
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            let feed = contract
                .get_verified_feed_data(
                    FEED_1.into(),
                    hex_payload(&payload),
                    MAX_PACKAGE_COUNT,
                    200,
                    10,
                )
                .expect("feed should be present and fresh");
            assert_eq!(feed.price, U128(42));
            assert_eq!(feed.timestamp, 1_700_000_000);
        }

        #[test]
        fn missing_feed_returns_none() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Two packages present, but query an id that is absent.
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            assert!(
                contract
                    .get_verified_feed_data(
                        FEED_999.into(),
                        hex_payload(&payload),
                        MAX_PACKAGE_COUNT,
                        200,
                        10,
                    )
                    .is_none()
            );
        }

        #[test]
        fn too_old_returns_none() {
            set_ctx_at(1_700_000_100); // 100s later, but max_delay is only 50
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            assert!(
                contract
                    .get_verified_feed_data(
                        FEED_1.into(),
                        hex_payload(&payload),
                        MAX_PACKAGE_COUNT,
                        50,
                        10,
                    )
                    .is_none()
            );
        }

        #[test]
        fn future_returns_none() {
            set_ctx_at(1_700_000_000);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Feed timestamp is 100s ahead of now, but max_future_drift is only 10.
            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_100u64)]);
            assert!(
                contract
                    .get_verified_feed_data(
                        FEED_1.into(),
                        hex_payload(&payload),
                        MAX_PACKAGE_COUNT,
                        200,
                        10,
                    )
                    .is_none()
            );
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn tampered_data_fails() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            payload[10] ^= 0x01; // tamper -> signature recovers a different address
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn wrong_signer_fails() {
            set_ctx_at(1_700_000_100);
            let signing = fixed_key();
            // Contract authorizes a DIFFERENT signer than the one that signs.
            let other = key_from_byte(9);
            let contract = contract_for(&other);

            let payload = build_payload(&signing, &[(1u32, 100u128, 1_700_000_000u64)]);
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Feed Data Count 2 exceeds maximum 1")]
        fn max_package_count_below_actual_panics() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Payload has 2 packages, but the caller caps max_package_count at 1.
            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&payload),
                1, // cap below actual count -> rejected by parse_metadata
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Invalid magic marker")]
        fn bad_magic_fails() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            let n = payload.len();
            payload[n - 1] ^= 0xFF; // corrupt the tail magic marker
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Payload too short")]
        fn too_short_fails() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&[0u8; MIN_PAYLOAD_LEN - 1]),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Payload length does not match count")]
        fn count_mismatch_fails() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            let count_pos = payload.len() - META_TAIL_LEN;
            payload[count_pos] = 5; // claim 5 packages, but only 1 present
            let _ = contract.get_verified_feed_data(
                FEED_1.into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Feed id must be 4 bytes")]
        fn bad_feed_id_len_panics() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            // 3-byte feed id (6 hex chars) is rejected.
            let _ = contract.get_verified_feed_data(
                "0x000001".into(),
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }
    }

    mod get_verified_feed_data_batch {
        use super::*;

        #[test]
        fn index_aligned() {
            set_ctx_at(1_700_000_100); // 100s after the feeds' timestamps
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            // Query: present feed 2, present feed 1, and an absent feed 999.
            let out = contract.get_verified_feed_data_batch(
                vec!["0x00000002".into(), FEED_1.into(), FEED_999.into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );

            assert_eq!(out.len(), 3);
            // feed 2
            let f2 = out[0].as_ref().unwrap();
            assert_eq!(f2.price, U128(99));
            assert_eq!(f2.timestamp, 1_700_000_050);
            // feed 1
            let f1 = out[1].as_ref().unwrap();
            assert_eq!(f1.price, U128(42));
            assert_eq!(f1.timestamp, 1_700_000_000);
            // feed 999 absent
            assert!(out[2].is_none());
        }

        #[test]
        fn marks_stale_as_none() {
            set_ctx_at(1_700_000_100); // max_delay 50 makes the feed too old
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(&sk, &[(1u32, 42u128, 1_700_000_000u64)]);
            let out = contract.get_verified_feed_data_batch(
                vec![FEED_1.into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                50,
                10,
            );
            assert_eq!(out.len(), 1);
            assert!(out[0].is_none());
        }

        #[test]
        fn mixes_fresh_and_stale() {
            // now = 1_700_000_100, max_delay = 60:
            //   feed 1 @1_700_000_000 -> 100s old > 60 -> stale -> None
            //   feed 2 @1_700_000_050 ->  50s old < 60 -> fresh -> Some
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            let out = contract.get_verified_feed_data_batch(
                vec![FEED_1.into(), "0x00000002".into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                60,
                10,
            );

            assert_eq!(out.len(), 2);
            assert!(out[0].is_none()); // feed 1 too old
            let f2 = out[1].as_ref().unwrap();
            assert_eq!(f2.price, U128(99)); // feed 2 still fresh
            assert_eq!(f2.timestamp, 1_700_000_050);
        }

        #[test]
        fn empty_ids_returns_empty() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            // Empty ids short-circuit without authenticating -> empty vector.
            let out = contract.get_verified_feed_data_batch(
                vec![],
                hex_payload(&Vec::new()),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
            assert!(out.is_empty());
        }

        #[test]
        #[should_panic(expected = "Signer address is not authorized")]
        fn untrusted_payload_panics() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let mut payload = build_payload(&sk, &[(1u32, 100u128, 1_700_000_000u64)]);
            payload[10] ^= 0x01; // tamper -> recovers an unauthorized signer
            let _ = contract.get_verified_feed_data_batch(
                vec![FEED_1.into()],
                hex_payload(&payload),
                MAX_PACKAGE_COUNT,
                200,
                10,
            );
        }

        #[test]
        #[should_panic(expected = "Feed Data Count 2 exceeds maximum 1")]
        fn max_package_count_below_actual_panics() {
            set_ctx_at(1_700_000_100);
            let sk = fixed_key();
            let contract = contract_for(&sk);

            let payload = build_payload(
                &sk,
                &[
                    (1u32, 42u128, 1_700_000_000u64),
                    (2u32, 99u128, 1_700_000_050u64),
                ],
            );
            // 2 packages but cap at 1 -> rejected by parse_metadata.
            let _ = contract.get_verified_feed_data_batch(
                vec![FEED_1.into()],
                hex_payload(&payload),
                1,
                200,
                10,
            );
        }
    }
}
