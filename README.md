# Pull Oracle Verifier (NEAR)

A **stateless, view-based** price verifier for NEAR, built to be called from other on-chain contracts — DEXs, lending protocols, derivatives, and similar.

A consumer contract receives a signed price payload from the oracle backend and passes it through to `get_verified_feed_data`. The verifier recovers the signer's EVM address, checks it is an authorized signer, and returns the requested feed.

The consumer can therefore trust a price's origin cryptographically — no need to trust the caller or the raw payload — while the verifier itself stays stateless and never holds a price.

The getters are read-only, so they can also be called for **free** via an RPC view call (off-chain frontends and indexers). On-chain consumers call them via a cross-contract call and read the result in a callback — see [Building a consumer contract](#building-a-consumer-contract).

## Payload layout

The payload is laid out and parsed **from the tail**:

```text
[ Package 1 ][ Package 2 ]...[ Package N ][ Count(N) : 1 ][ Signature : 65 ][ Magic Marker : 2 ]
```

- **Signed data** = `Packages || Count` — everything except the trailing 67 bytes (`Signature` + `Magic Marker`).
- **Magic Marker** = `0x7096` — the first two bytes of `keccak256("ATLAS")`. It is **enforced**: the call panics with `"Invalid magic marker"` if the trailing 2 bytes do not match.

Each **package** is 20 bytes, all fields big-endian:

| Offset | Field     | Bytes | Decoded type    |
|--------|-----------|-------|-----------------|
| 0      | Feed ID   | 4     | `u32`           |
| 4      | Value     | 10    | `u128`          |
| 14     | Timestamp | 6     | `u64` (seconds) |

`Value` and `Timestamp` are stored in their low-order bytes: decoding left-pads them with zeros to 16 / 8 bytes big-endian.

## Methods

The four feed getters are the public query API.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_verified_feed_data(feed_id, payload, max_package_count, max_delay, max_future_drift)` | `Option<FeedData>` | Authenticate, then return the feed matching `feed_id` when present and fresh; else `None` |
| `get_verified_feed_data_batch(feed_ids, payload, max_package_count, max_delay, max_future_drift)` | `Vec<Option<FeedData>>` | Authenticate once, then one entry per id, index-aligned; empty `feed_ids` returns an empty vector |
| `get_feed_data_unchecked(feed_id, payload, max_package_count)` | `Option<FeedData>` | Authenticate + look up WITHOUT the freshness check — the feed may be stale; caller MUST inspect `timestamp` |
| `get_feed_data_unchecked_batch(feed_ids, payload, max_package_count)` | `Vec<Option<FeedData>>` | Batch variant of the above |

- `payload`: the raw payload bytes, hex-encoded with a `0x` prefix.
- `max_package_count`: caller-supplied cap on how many feed packages the payload may carry; panics if the payload's count exceeds it.
- `max_delay` / `max_future_drift`: bounds (in **seconds**) on the selected feed's timestamp relative to block time — it must fall within `[now - max_delay, now + max_future_drift]`.
- `feed_id`: which feed to select, a `0x`-prefixed 8-hex-char string (EVM `bytes4`). Feed ids are assigned by the oracle backend — get the id-to-asset registry from the operator.

> `max_package_count`, `max_delay`, and `max_future_drift` are verification policy, not user input: a business contract should fix them itself (hardcoded or admin-configured) and never forward end-user values. An oversized `max_package_count` admits larger signed payloads (resource/DoS surface), an oversized `max_delay` weakens stale-price protection, and an oversized `max_future_drift` weakens future-timestamp protection. `payload` and `feed_id`, by contrast, are safe to accept from callers — the verifier authenticates the payload's signature, and the feed id only selects an entry within it.

The getters return **borsh-encoded** results (`#[result_serializer(borsh)]`), which are cheaper to serialize and deserialize than JSON — saving gas on cross-contract calls. The same bytes reach both RPC view callers and cross-contract callbacks. `FeedData` borsh layout:

```text
Option<FeedData>      = [variant: 1 byte (0 = None, 1 = Some)][FeedData]
FeedData              = [price: u128 — 16 bytes LE][timestamp: u64 — 8 bytes LE]
Vec<Option<FeedData>> = [length: u32 LE][entry]...   (batch getters)
```

> **Failure modes are split:**
> - **Panics (reverts)** on an invalid payload — bad framing, an invalid or non-canonical signature, or an unauthorized signer. Treat an RPC error as "invalid/untrusted payload".
> - **Returns `None`** when the payload is valid but has no usable feed — the `feed_id` is absent, or its timestamp is out of range. Callers can fall back or skip.

## Signature trust domain

All deployments and consumer contracts that verify this payload share a single **signature trust domain**: a payload signed by an authorized signer is accepted anywhere that signer is trusted.

Consumer contracts that verify and parse the payload themselves embed the signer address locally, so when the oracle rotates or revokes a signer they must update their own contract to stay in sync — this drift across deployments during rotation is expected.

Because the same signature is trusted across the whole domain, we keep the signing key dedicated to this Pull Oracle payload format and do not reuse it for other protocols or other message formats.

## Building a consumer contract

NEAR cross-contract calls are asynchronous: a consumer dispatches a Promise to the verifier and reads the result in a callback. See [`examples/consumer`](https://github.com/oracle-atlas/near-pull-verifier/tree/main/examples/consumer) for a complete, runnable reference implementation.

## Development

Prerequisites:

- [Rust](https://rustup.rs) — version pinned by `rust-toolchain.toml`.
- [`cargo-near`](https://github.com/near/cargo-near) — builds the WASM artifact.
- [`just`](https://github.com/casey/just) — the project task runner.

### Build

```bash
just build            # fast, non-reproducible WASM -> target/near/pull_verifier.wasm
just build-release    # reproducible WASM (via Docker, requires committed git state)
```

### Test

```bash
just test             # unit tests + sandbox integration test
just test-consumer    # cross-contract end-to-end test (consumer example)
```

### Size

```bash
just size             # rebuild and print the WASM size in bytes
just size-only        # print the size without rebuilding
```

### Clean

```bash
just clean
```
