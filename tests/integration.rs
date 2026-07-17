use alloy::primitives::keccak256;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use near_api::AccountId;
use near_api::NearToken;
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
    p.extend_from_slice(&feed_id.to_be_bytes()); // 4 bytes
    p.extend_from_slice(&value.to_be_bytes()[6..]); // low 10 of 16 bytes
    p.extend_from_slice(&timestamp.to_be_bytes()[2..]); // low 6 of 8 bytes
    p
}

/// Assemble a full payload: [packages][count][sig(65)][magic(2)].
fn build_payload(signer: &PrivateKeySigner, feeds: &[(u32, u128, u64)]) -> Vec<u8> {
    let mut raw_data = Vec::new();
    for (id, v, t) in feeds {
        raw_data.extend_from_slice(&package(*id, *v, *t));
    }
    raw_data.push(feeds.len() as u8); // Packages || Count

    let sig = sign_eth(signer, &raw_data);

    let mut payload = raw_data;
    payload.extend_from_slice(&sig);
    payload.extend_from_slice(&[0x70, 0x96]); // magic marker = keccak256("ATLAS")[..2]
    payload
}

#[derive(near_sdk::serde::Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
struct FeedData {
    price: near_sdk::json_types::U128,
    timestamp: u64,
}

async fn test_verifier_on(contract_wasm: Vec<u8>) -> testresult::TestResult<()> {
    let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
    let sandbox_network =
        near_api::NetworkConfig::from_rpc_url("sandbox", sandbox.rpc_addr.parse()?);

    let owner = create_subaccount(&sandbox, "owner.sandbox").await?;
    let contract = create_subaccount(&sandbox, "contract.sandbox")
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

    // Deploy + initialize with the trusted signer address as an authorized signer.
    near_api::Contract::deploy(contract.account_id().clone())
        .use_code(contract_wasm)
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

    // is_signer confirms the oracle address is authorized.
    let is_authorized: bool = contract
        .call_function(
            "is_signer",
            json!({ "evm_address_hex": authorized_signer_addr }),
        )
        .read_only()
        .fetch_from(&sandbox_network)
        .await?
        .data;
    assert!(is_authorized);

    // A different address is not authorized.
    let not_authorized: bool = contract
        .call_function(
            "is_signer",
            json!({ "evm_address_hex": "0x000000000000000000000000000000000000dead" }),
        )
        .read_only()
        .fetch_from(&sandbox_network)
        .await?
        .data;
    assert!(!not_authorized);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Two feeds: feed 1 stamped at `now` (fresh), feed 0xdeadbeef stamped 1000s
    // ago (stale under the tight 10s freshness window used below).
    let feeds_in = [
        (1u32, 123_456u128, now),                         // fresh
        (0xDEAD_BEEFu32, (1u128 << 72) + 42, now - 1000), // stale (1000s old)
    ];
    let payload = build_payload(&authorized_signer, &feeds_in);
    let payload_hex = format!("0x{}", hex::encode(&payload));

    // feed 1 was stamped at `now`, so it is fresh within the tight 10s window.
    let feed: Option<FeedData> = contract
        .call_function(
            "get_verified_feed_data",
            json!({
                "payload": payload_hex,
                "max_delay": 10u64,
                "max_future_drift": 10u64,
                "feed_id": "0x00000001",
                "max_package_count": 32,
            }),
        )
        .read_only()
        .fetch_from(&sandbox_network)
        .await?
        .data;

    let feed = feed.expect("feed should be present and fresh");
    assert_eq!(feed.price.0, 123_456);
    assert_eq!(feed.timestamp, now);

    // Batch: authenticate once, look up several ids, index-aligned.
    let batch: Vec<Option<FeedData>> = contract
        .call_function(
            "get_verified_feed_data_batch",
            json!({
                "feed_ids": ["0x00000001", "0xdeadbeef", "0x000003e7"],
                "payload": payload_hex,
                "max_package_count": 32,
                "max_delay": 10u64,
                "max_future_drift": 10u64,
            }),
        )
        .read_only()
        .fetch_from(&sandbox_network)
        .await?
        .data;

    assert_eq!(batch.len(), 3);
    let f1 = batch[0].as_ref().expect("feed 1 present");
    assert_eq!(f1.price.0, 123_456);
    assert_eq!(f1.timestamp, now);
    assert!(batch[1].is_none()); // 0xdeadbeef present but stale -> filtered out
    assert!(batch[2].is_none()); // 0x000003e7 (999) absent

    // Tampered payload must fail verification.
    let mut bad = build_payload(&authorized_signer, &feeds_in);
    bad[10] ^= 0x01;
    let bad_hex = format!("0x{}", hex::encode(&bad));
    let res: Result<near_api::Data<Option<FeedData>>, _> = contract
        .call_function(
            "get_verified_feed_data",
            json!({
                "payload": bad_hex,
                "max_delay": 10u64,
                "max_future_drift": 10u64,
                "feed_id": "0x00000001",
                "max_package_count": 32,
            }),
        )
        .read_only()
        .fetch_from(&sandbox_network)
        .await;
    assert!(res.is_err(), "tampered payload should fail verification");

    Ok(())
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

#[tokio::test]
async fn test_contract_is_operational() -> testresult::TestResult<()> {
    let contract_wasm_path = cargo_near_build::build_with_cli(Default::default())?;
    let contract_wasm = std::fs::read(contract_wasm_path)?;

    test_verifier_on(contract_wasm).await
}
