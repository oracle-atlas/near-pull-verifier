# Pull Verifier Consumer Example

Example consumer contract demonstrating the on-chain pull pattern: call the [Pull Verifier](../../) via a cross-contract call (Promise) and read the verified price in a callback.

**Not audited — for integration reference and end-to-end testing only.**

## Build

```bash
cargo near build non-reproducible-wasm
```

## Test

End-to-end tests require both the verifier and consumer wasm. From the **project root**:

```bash
just test-consumer
```

Or manually:

```bash
# Build verifier first
cargo near build non-reproducible-wasm
# Build consumer
cargo near build non-reproducible-wasm --manifest-path examples/consumer/Cargo.toml
# Run tests
cargo test --manifest-path examples/consumer/Cargo.toml
```

## Key Files

- `src/ext.rs` — self-contained cross-contract interface (`FeedData` + `#[ext_contract]` trait). Copy this file into your own project to integrate with the verifier.
- `src/lib.rs` — consumer contract logic (cross-contract call + callback + storage).
