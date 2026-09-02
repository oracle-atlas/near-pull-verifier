//! Example consumer for the Pull Verifier — NOT AUDITED.
//!
//! Demonstrates the on-chain pull pattern: call the verifier via a
//! cross-contract call (Promise) and read the result in a callback. For
//! integration reference and end-to-end testing only.

pub mod ext;

use near_sdk::{
    AccountId, BorshStorageKey, Gas, PanicOnDefault, Promise, PromiseError, env, near,
    store::LookupMap,
};

use ext::{FeedData, ext_pull_verifier};

const GAS: Gas = Gas::from_tgas(30);

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Feeds,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Consumer {
    /// The deployed pull-verifier account.
    verifier: AccountId,
    /// Latest FeedData received per feed_id (feed_id hex string -> FeedData).
    feeds: LookupMap<String, FeedData>,
}

#[near]
impl Consumer {
    #[init]
    pub fn new(verifier: AccountId) -> Self {
        Self {
            verifier,
            feeds: LookupMap::new(StorageKey::Feeds),
        }
    }

    /// Pull one feed: verify the payload via the verifier, then store the
    /// result in the callback. Cross-contract calls are async, so the price
    /// is available only after `on_price` runs — query it via `get_feed`.
    pub fn use_price(
        &mut self,
        payload: String,
        feed_id: String,
        max_delay: u64,
        max_future_drift: u64,
    ) -> Promise {
        ext_pull_verifier::ext(self.verifier.clone())
            .with_static_gas(GAS)
            .get_verified_feed_data(feed_id.clone(), payload, 32, max_delay, max_future_drift)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS)
                    .on_price(feed_id),
            )
    }

    /// Callback: store the verified feed (if present and fresh) under its id.
    #[private]
    pub fn on_price(
        &mut self,
        feed_id: String,
        #[callback_result]
        #[serializer(borsh)]
        result: Result<Option<FeedData>, PromiseError>,
    ) {
        match result {
            Ok(Some(feed)) => {
                env::log_str(&format!("Stored feed {feed_id}: price={}", feed.price.0));
                self.feeds.insert(feed_id, feed);
            }
            Ok(None) => env::log_str(&format!("Feed {feed_id} absent or stale")),
            Err(_) => env::log_str("Verifier rejected the payload (untrusted)"),
        }
    }

    /// Query a stored feed by id (for tests / inspection).
    pub fn get_feed(&self, feed_id: String) -> Option<FeedData> {
        self.feeds.get(&feed_id).cloned()
    }
}
