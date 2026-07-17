# Pull Oracle Verifier (NEAR)

A **stateless, view-based** price verifier contract for NEAR.

Clients fetch a signed price payload from the backend API and pass it to the
contract's `get_verified_feed_data` method. The contract:

1. Recovers the ECDSA signer's **EVM address** from the signature over
   `keccak256(Packages || Count)` (`ecrecover` → `keccak256(pubkey)[12..]`).
2. Checks the recovered address is one of the trusted **authorized signers**
   stored on-chain.
3. Scans the packages for the one matching `feed_id` (stopping at the first
   match), checks its timestamp is recent, and returns it — or `None` if the
   feed is absent or stale.

Because `get_verified_feed_data` is read-only (`&self`), it can be called for
**free** via an RPC `query` (view) call — no gas paid, nothing written on-chain.
On-chain consumer contracts can also call it via a cross-contract call and decode
the borsh result in their callback.

## Payload layout

The payload is laid out (and parsed from the **tail**) as:

```
[ Feed Data Packages : N * 20 ][ Count(N) : 1 ][ Signature : 65 ][ Magic Marker : 2 ]
```

- **Signed data** = `Packages || Count` (the first `N*20 + 1` bytes).
- `Signature` and `Magic Marker` are NOT part of the signed data.
- **Magic Marker** is fixed to `0x7096` — the first two bytes of
  `keccak256("ATLAS")` — and is **enforced**: the call panics with
  `"Invalid magic marker"` if the tail 2 bytes do not match.

Each **Feed Data package** is 20 bytes, all fields big-endian:

| Field      | Bytes | Type in result           |
|------------|-------|--------------------------|
| Feed ID    | 4     | `u32`                    |
| Value      | 10    | `U128` (string in JSON)  |
| Timestamp  | 6     | `u64` (seconds)          |

### Signature scheme (backend)

```
RawData     = [Package 1][Package 2]...[Package N][Count]
MessageHash = Keccak256(RawData)
Signature   = ECDSA_Sign(PrivateKey, MessageHash)   // secp256k1, r(32)||s(32)||v(1)
```

The `v` byte must be **Ethereum-style `v ∈ {27, 28}`** — any other value
(including raw `0/1` or EIP-155 transaction `v`) is rejected with
`"Invalid recovery id"`. The contract also enforces **EIP-2 low-s**: a
non-canonical (high-s) signature is rejected as
`"Invalid or non-canonical signature"`.


## Methods

| Method | Kind | Description |
|--------|------|-------------|
| `new(owner, initial_signers)` | init | Store owner + initial set of authorized signer addresses. `initial_signers` may be empty (no signer authorized until `set_signer` adds one). Emits `signer_status_changed` per signer and `ownership_transferred` |
| `get_verified_feed_data(feed_id, payload, max_package_count, max_delay, max_future_drift) -> Option<FeedData>` | **view** | Authenticate, then scan for the feed matching `feed_id`; return it if present and fresh, else `None`. Panics on an invalid/unauthorized payload |
| `get_verified_feed_data_batch(feed_ids, payload, max_package_count, max_delay, max_future_drift) -> Vec<Option<FeedData>>` | **view** | Same as above but for many ids; authenticates once, returns one entry per id (index-aligned). An empty `feed_ids` returns an empty vector without authenticating |
| `get_feed_data_unchecked(feed_id, payload, max_package_count) -> Option<FeedData>` | **view** | Authenticate + look up `feed_id`, but skip the freshness check — may return a stale price. Caller MUST check `timestamp` itself |
| `get_feed_data_unchecked_batch(feed_ids, payload, max_package_count) -> Vec<Option<FeedData>>` | **view** | Same as above but for many ids; authenticates once, returns one entry per id (index-aligned). An empty `feed_ids` returns an empty vector without authenticating |
| `set_signer(evm_address_hex, add)` | call, owner-only | Add (`add=true`) or remove (`add=false`) an authorized signer. **Panics** if the signer is already in the requested state (a no-op add/remove). Emits `signer_status_changed` |
| `is_signer(evm_address_hex) -> bool` | view | Whether the given EVM address is an authorized signer |
| `get_owner() -> AccountId` | view | Current owner |
| `transfer_ownership(new_owner)` | call, owner-only | Transfer ownership (immediate; double-check the target). Emits `ownership_transferred` |

- `initial_signers` / `evm_address_hex`: signer **EVM addresses** — a `0x`-prefixed
  hex string of 40 hex characters (20 bytes). The `0x` prefix is **required**.
  An address is derived from the uncompressed secp256k1 public key as
  `keccak256(pubkey)[12..]`.
- `payload`: the raw payload bytes, hex-encoded with a `0x` prefix.
- `max_package_count`: caller-supplied cap on how many feed packages the payload
  may carry; panics if the payload's count exceeds it.
- `max_delay` / `max_future_drift`: bounds (in **seconds**) on the selected feed's
  timestamp relative to block time — it must fall within
  `[now - max_delay, now + max_future_drift]`.
- `feed_id`: which feed to select, a `0x`-prefixed 8-hex-char string (EVM `bytes4`).

`FeedData` JSON shape:

```json
{ "price": "123456", "timestamp": 1700000000 }
```

> **Failure modes are split:**
> - **Panics (reverts)** on an invalid payload — bad framing, an invalid or
>   non-canonical signature, or an unauthorized signer. Treat an RPC error as
>   "invalid/untrusted payload".
> - **Returns `None`** when the payload is valid but has no usable feed — the
>   `feed_id` is absent, or its timestamp is out of range. Callers can fall back
>   or skip.

## Events (NEP-297)

The contract emits standard [NEP-297](https://nomicon.io/Standards/EventsFormat)
events (`standard: "pull_verifier"`, `version: "1.0.0"`) so off-chain indexers
can track changes to the trust root (authorized signers) and ownership:

- **`signer_status_changed`** `{ signer, added }` — emitted by `new` (once per
  initial signer, `added: true`) and by `set_signer`.
- **`ownership_transferred`** `{ old_owner, new_owner }` — emitted by `new`
  (with `old_owner: null` for the initial owner) and by `transfer_ownership`.

Each event is a log line of the form:

```
EVENT_JSON:{"standard":"pull_verifier","version":"1.0.0","event":"signer_status_changed","data":[{"signer":"0x...","added":true}]}
```

NEAR nodes do not offer an `eth_getLogs`-style query; index these events
off-chain (e.g. via the [NEAR Lake Framework](https://docs.near.org/tools/near-lake-framework)
or a subgraph) to filter them by block range.

## Build

Install [`cargo-near`](https://github.com/near/cargo-near) and run:

```bash
cargo near build
```

## Test

```bash
cargo test
```

Runs unit tests (signature / parse / decode logic) plus a NEAR sandbox
integration test that deploys the contract and exercises `get_verified_feed_data`
and `get_verified_feed_data_batch` end-to-end.

## Deploy

```bash
# debugging
cargo near deploy build-non-reproducible-wasm

# production
cargo near deploy build-reproducible-wasm
```

## Initialize

```bash
near contract call-function as-transaction '<CONTRACT_ACCOUNT_ID>' new \
  json-args '{"owner": "<OWNER_ACCOUNT_ID>", "initial_signers": ["0x<40_HEX_CHARS>"]}' \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  sign-as '<CONTRACT_ACCOUNT_ID>' network-config testnet sign-with-keychain send
```

## Call `get_verified_feed_data` (view)

`payload` is the hex-encoded payload bytes (with a `0x` prefix):

```bash
near contract call-function as-read-only '<CONTRACT_ACCOUNT_ID>' get_verified_feed_data \
  json-args '{"payload": "0x<HEX_PAYLOAD>", "max_delay": 60, "max_future_drift": 5, "feed_id": "0x<8_HEX_CHARS>", "max_package_count": 32}' \
  network-config testnet now
```

Returns the matching feed when present and fresh, or `null` otherwise:

```json
{ "price": "123456", "timestamp": 1700000000 }
```

To fetch several feeds from one payload in a single call, use
`get_verified_feed_data_batch` with a `feed_ids` array; it authenticates the
payload once and returns one entry per id (index-aligned, `null` when a feed is
absent or stale):

```json
["0x00000001", "0x00000002"]  ->  [ { "price": "123456", "timestamp": 1700000000 }, null ]
```

## Manage authorized signers (owner-only)

```bash
# add a signer address
near contract call-function as-transaction '<CONTRACT_ACCOUNT_ID>' set_signer \
  json-args '{"evm_address_hex": "0x<40_HEX_CHARS>", "add": true}' \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  sign-as '<OWNER_ACCOUNT_ID>' network-config testnet sign-with-keychain send

# remove a signer address: same call with "add": false
```

> `set_signer` rejects **no-op** changes: adding an already-authorized signer,
> or removing one that is not authorized, panics with
> `"Signer already in the requested state"`.

Check whether an address is an authorized signer:

```bash
near contract call-function as-read-only '<CONTRACT_ACCOUNT_ID>' is_signer \
  json-args '{"evm_address_hex": "0x<40_HEX_CHARS>"}' network-config testnet now
```

> The full list of authorized signers is not enumerable on-chain (a `LookupSet`
> is used to minimize gas/storage). Track the set off-chain (backend/config,
> or by indexing the `signer_status_changed` events) and use `is_signer` to
> verify a specific address on-chain.

## Notes for on-chain consumers

NEAR contracts cannot synchronously read another contract's view return value —
cross-contract calls are asynchronous (Promise + callback). If another contract
needs these prices on-chain, it should use the pull pattern: pass the signed
payload into its own method, call `get_verified_feed_data` via a cross-contract
call, and continue in the callback where it decodes the borsh-encoded `FeedData`.
Front-ends / off-chain services can call `get_verified_feed_data` directly and
synchronously via an RPC view call.