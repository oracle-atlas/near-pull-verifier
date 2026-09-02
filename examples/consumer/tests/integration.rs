use alloy::{
    primitives::keccak256,
    signers::{SignerSync, local::PrivateKeySigner},
};
use consumer::ext::FeedData;
use near_api::{AccountId, NearGas, NearToken};
use near_sdk::serde_json::json;

/// The signer's EVM address as a `0x`-prefixed hex string (keccak256(pubkey)[12..]).
fn address_of(signer: &PrivateKeySigner) -> String {
    format!("0x{}", hex::encode(signer.address().into_array()))
}

/// Sign keccak256(raw_data) -> 65-byte r||s||v (Ethereum-style v 27/28).
fn sign_eth(signer: &PrivateKeySigner, raw_data: &[u8]) -> [u8; 65] {
    let sig = signer.sign_hash_sync(&keccak256(raw_data)).expect("sign");
    sig.as_bytes()
}

/// Build a 20-byte package (big-endian): [feed_id:4][value:10][timestamp:6].
fn package(feed_id: u32, value: u128, timestamp: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(20);
    p.extend_from_slice(&feed_id.to_be_bytes());
    p.extend_from_slice(&value.to_be_bytes()[6..]);
    p.extend_from_slice(&timestamp.to_be_bytes()[2..]);
    p
}

/// Assemble a full payload: [packages][count][sig(65)][magic(2)].
fn build_payload(signer: &PrivateKeySigner, feeds: &[(u32, u128, u64)]) -> Vec<u8> {
    let mut raw_data = Vec::new();
    for (id, v, t) in feeds {
        raw_data.extend_from_slice(&package(*id, *v, *t));
    }
    raw_data.push(feeds.len() as u8);

    let sig = sign_eth(signer, &raw_data);

    let mut payload = raw_data;
    payload.extend_from_slice(&sig);
    payload.extend_from_slice(&[0x70, 0x96]); // magic marker = keccak256("ATLAS")[..2]
    payload
}

async fn create_subaccount(
    sandbox: &near_sandbox::Sandbox,
    name: &str,
) -> testresult::TestResult<near_api::Account> {
    let account_id: AccountId = name.parse().unwrap();
    sandbox
        .create_account(account_id.clone())
        .initial_balance(NearToken::from_near(10))
        .send()
        .await?;
    Ok(near_api::Account(account_id))
}

/// Assert that the transaction logs contain a line starting with the given prefix.
fn assert_log_contains(logs: &[&str], prefix: &str) {
    assert!(
        logs.iter().any(|l| l.starts_with(prefix)),
        "expected log starting with \"{prefix}\", got: {logs:?}"
    );
}

#[tokio::test]
async fn test_consumer_e2e() -> testresult::TestResult<()> {
    let consumer_wasm_path = cargo_near_build::build_with_cli(Default::default())?;
    let consumer_wasm = std::fs::read(consumer_wasm_path)?;
    let verifier_wasm_path = cargo_near_build::build_with_cli(
        cargo_near_build::BuildOpts::builder()
            .manifest_path("../../Cargo.toml")
            .build(),
    )?;
    let verifier_wasm = std::fs::read(verifier_wasm_path)?;

    let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
    let sandbox_network =
        near_api::NetworkConfig::from_rpc_url("sandbox", sandbox.rpc_addr.parse()?);

    let owner = create_subaccount(&sandbox, "owner.sandbox").await?;
    let verifier = create_subaccount(&sandbox, "verifier.sandbox")
        .await?
        .as_contract();
    let consumer = create_subaccount(&sandbox, "consumer.sandbox")
        .await?
        .as_contract();

    let signer = near_api::Signer::from_secret_key(
        near_sandbox::config::DEFAULT_GENESIS_ACCOUNT_PRIVATE_KEY
            .parse()
            .unwrap(),
    )?;

    let authorized_signer: PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
    let authorized_signer_addr = address_of(&authorized_signer);

    // Deploy and initialize the verifier.
    near_api::Contract::deploy(verifier.account_id().clone())
        .use_code(verifier_wasm)
        .with_init_call(
            "new",
            json!({
                "owner": owner.account_id(),
                "initial_signers": [authorized_signer_addr.clone()],
            }),
        )?
        .with_signer(signer.clone())
        .send_to(&sandbox_network)
        .await?
        .assert_success();

    // Deploy and initialize the consumer, pointing it at the verifier.
    near_api::Contract::deploy(consumer.account_id().clone())
        .use_code(consumer_wasm)
        .with_init_call("new", json!({ "verifier": verifier.account_id() }))?
        .with_signer(signer.clone())
        .send_to(&sandbox_network)
        .await?
        .assert_success();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ── Scenario 1: fresh feed ──────────────────────────────────────

    let feeds_in = [(1u32, 123_456u128, now)];
    let payload_hex = format!(
        "0x{}",
        hex::encode(&build_payload(&authorized_signer, &feeds_in))
    );

    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": payload_hex,
                "feed_id": "0x00000001",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Stored feed 0x00000001");
    result.assert_success();

    let feed = consumer
        .call_function("get_feed", json!({ "feed_id": "0x00000001" }))
        .read_only::<Option<FeedData>>()
        .fetch_from(&sandbox_network)
        .await?
        .data
        .expect("fresh feed should be stored");
    assert_eq!(feed.price.0, 123_456);
    assert_eq!(feed.timestamp, now);

    // ── Scenario 2: stale feed ──────────────────────────────────────

    // Note: feed 0x00000001 still has the value from scenario 1 (consumer
    // only inserts on success, never deletes). We use a different feed_id
    // to test staleness cleanly.
    let feeds_in = [(2u32, 456_789u128, now - 1000)];
    let payload_hex = format!(
        "0x{}",
        hex::encode(&build_payload(&authorized_signer, &feeds_in))
    );

    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": payload_hex,
                "feed_id": "0x00000002",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Feed 0x00000002 absent or stale");
    result.assert_success();

    // ── Scenario 3: tampered payload ────────────────────────────────

    let feeds_in = [(3u32, 789_012u128, now)];
    let mut bad_payload = build_payload(&authorized_signer, &feeds_in);
    bad_payload[10] ^= 0x01;
    let bad_hex = format!("0x{}", hex::encode(&bad_payload));

    // The transaction succeeds (consumer dispatched the Promise), but the
    // verifier receipt panics. The callback receives PromiseError.
    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": bad_hex,
                "feed_id": "0x00000003",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Verifier rejected the payload (untrusted)");
    result.assert_success();

    // ── Scenario 4: absent feed_id ──────────────────────────────────

    // Payload contains feed 3, but we request feed 0x00000004 which is not
    // in the payload. Verifier returns None (B-class: find_feed misses).
    let feeds_in = [(3u32, 789_012u128, now)];
    let payload_hex = format!(
        "0x{}",
        hex::encode(&build_payload(&authorized_signer, &feeds_in))
    );

    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": payload_hex,
                "feed_id": "0x00000004",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Feed 0x00000004 absent or stale");
    result.assert_success();

    // ── Scenario 5: multi-feed payload ──────────────────────────────

    let feeds_in = [(1u32, 123_456u128, now), (0xDEAD_BEEFu32, 999_999u128, now)];
    let payload_hex = format!(
        "0x{}",
        hex::encode(&build_payload(&authorized_signer, &feeds_in))
    );

    // Pull feed 1.
    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": payload_hex,
                "feed_id": "0x00000001",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Stored feed 0x00000001");
    result.assert_success();

    let feed = consumer
        .call_function("get_feed", json!({ "feed_id": "0x00000001" }))
        .read_only::<Option<FeedData>>()
        .fetch_from(&sandbox_network)
        .await?
        .data
        .expect("feed 1 should be stored");
    assert_eq!(feed.price.0, 123_456);
    assert_eq!(feed.timestamp, now);

    // Pull feed 0xdeadbeef with the same payload.
    let result = consumer
        .call_function(
            "use_price",
            json!({
                "payload": payload_hex,
                "feed_id": "0xdeadbeef",
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(100))
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&sandbox_network)
        .await?;
    assert_log_contains(&result.logs(), "Stored feed 0xdeadbeef");
    result.assert_success();

    let feed = consumer
        .call_function("get_feed", json!({ "feed_id": "0xdeadbeef" }))
        .read_only::<Option<FeedData>>()
        .fetch_from(&sandbox_network)
        .await?
        .data
        .expect("feed 0xdeadbeef should be stored");
    assert_eq!(feed.price.0, 999_999);
    assert_eq!(feed.timestamp, now);

    Ok(())
}
