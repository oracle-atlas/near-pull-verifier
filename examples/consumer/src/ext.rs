//! Cross-contract interface for the Pull Verifier.
//!
//! Mirrors the verifier's public view methods — method names and parameter
//! types must match exactly for the Promise call to resolve correctly.

use near_sdk::{AccountId, ext_contract, json_types::U128, near};

/// A duration or timestamp expressed in whole seconds. Serializes as `u64`.
pub type Seconds = u64;

/// A single decoded Feed Data package: price + aggregation timestamp.
///
/// Must match the verifier's `FeedData` borsh layout (same field order; `U128`
/// serializes as `u128`): the verifier returns borsh (`#[result_serializer(borsh)]`)
/// and `on_price`'s callback argument decodes it with `#[serializer(borsh)]`.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedData {
    pub price: U128,
    pub timestamp: Seconds,
}
// The trait itself is only consumed by the #[ext_contract] macro.
#[allow(dead_code)]
// The generated `ext_pull_verifier` module is what callers use.
#[ext_contract(ext_pull_verifier)]
pub trait PullVerifier {
    /// Return the feed matching `feed_id`, verifying the payload and the feed's
    /// freshness.
    ///
    /// The feed's timestamp must lie within `[now - max_delay, now +
    /// max_future_drift]` (block time, seconds).
    ///
    /// # Arguments
    /// * `feed_id` - a `0x`-prefixed 8-hex-char string (EVM `bytes4`)
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages the
    ///   payload may carry. Set it in the calling contract, not from user
    ///   input, since oversized caps admit larger signed payloads.
    /// * `max_delay` - how many seconds the feed timestamp may lag the
    ///   block time. Set it in the calling contract, not from user input,
    ///   since oversized values weaken stale-price protection.
    /// * `max_future_drift` - how many seconds the feed timestamp may run
    ///   ahead of the block time. Set it in the calling contract, not from
    ///   user input, since oversized values weaken future-timestamp
    ///   protection.
    ///
    /// # Panics
    /// Panics on an untrusted payload (bad framing, invalid/non-canonical
    /// signature, or unauthorized signer) or a malformed `feed_id`.
    ///
    /// # Returns
    /// `Some(feed)` if present and fresh; `None` if the feed is absent or its
    /// timestamp is out of range (so callers can fall back or skip).
    fn get_verified_feed_data(
        &self,
        feed_id: String,
        payload: String,
        max_package_count: u8,
        max_delay: Seconds,
        max_future_drift: Seconds,
    ) -> Option<FeedData>;

    /// Batch [`PullVerifier::get_verified_feed_data`]: authenticate the payload once,
    /// then look up each id in `feed_ids`.
    ///
    /// # Arguments
    /// * `feed_ids` - `0x`-prefixed 8-hex-char (EVM `bytes4`) ids to look up
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages the
    ///   payload may carry. Set it in the calling contract, not from user
    ///   input, since oversized caps admit larger signed payloads.
    /// * `max_delay` - how many seconds the feed timestamp may lag the
    ///   block time. Set it in the calling contract, not from user input,
    ///   since oversized values weaken stale-price protection.
    /// * `max_future_drift` - how many seconds the feed timestamp may run
    ///   ahead of the block time. Set it in the calling contract, not from
    ///   user input, since oversized values weaken future-timestamp
    ///   protection.
    ///
    /// # Panics
    /// Panics (failing the whole call) on an untrusted payload or any malformed
    /// `feed_id`.
    ///
    /// # Returns
    /// One entry per input id, index-aligned: `Some(feed)` if present and fresh,
    /// else `None` when that feed is absent or its timestamp is out of range.
    /// An empty `feed_ids` yields an empty vector.
    fn get_verified_feed_data_batch(
        &self,
        feed_ids: Vec<String>,
        payload: String,
        max_package_count: u8,
        max_delay: Seconds,
        max_future_drift: Seconds,
    ) -> Vec<Option<FeedData>>;

    /// Return the feed matching `feed_id` WITHOUT any freshness check.
    ///
    /// The payload is still fully authenticated (signature + authorized signer),
    /// so the data's origin is trusted — but its timestamp is NOT validated, so
    /// it may be stale. Prefer [`PullVerifier::get_verified_feed_data`] unless
    /// you need to apply your own freshness policy.
    ///
    /// # Arguments
    /// * `feed_id` - a `0x`-prefixed 8-hex-char string (EVM `bytes4`)
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages the
    ///   payload may carry. Set it in the calling contract, not from user
    ///   input, since oversized caps admit larger signed payloads.
    ///
    /// # Panics
    /// Panics on an untrusted payload or any malformed `feed_id`.
    ///
    /// # Returns
    /// `Some(feed)` if present (possibly stale — callers MUST inspect
    /// `FeedData::timestamp`), or `None` if the feed is absent.
    fn get_feed_data_unchecked(
        &self,
        feed_id: String,
        payload: String,
        max_package_count: u8,
    ) -> Option<FeedData>;

    /// Batch [`PullVerifier::get_feed_data_unchecked`]: authenticate the payload once,
    /// then look up each id in `feed_ids` WITHOUT a freshness check.
    ///
    /// # Arguments
    /// * `feed_ids` - `0x`-prefixed 8-hex-char (EVM `bytes4`) ids to look up
    /// * `payload` - the `0x`-prefixed hex-encoded signed payload
    /// * `max_package_count` - upper bound on the number of packages the
    ///   payload may carry. Set it in the calling contract, not from user
    ///   input, since oversized caps admit larger signed payloads.
    ///
    /// # Panics
    /// Panics on an untrusted payload or any malformed `feed_id`.
    ///
    /// # Returns
    /// One entry per input id, index-aligned: `Some(feed)` if present, else
    /// `None`. Feeds may be stale — callers MUST inspect each
    /// `FeedData::timestamp`. An empty `feed_ids` yields an empty vector.
    fn get_feed_data_unchecked_batch(
        &self,
        feed_ids: Vec<String>,
        payload: String,
        max_package_count: u8,
    ) -> Vec<Option<FeedData>>;

    /// Whether the given EVM address is an authorized signer.
    ///
    /// # Arguments
    /// * `evm_address_hex` - a `0x`-prefixed 40-hex-char EVM address.
    fn is_signer(&self, evm_address_hex: String) -> bool;

    /// Current owner account.
    fn get_owner(&self) -> AccountId;
}
