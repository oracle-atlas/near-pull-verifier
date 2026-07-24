# Pull Verifier Consumer Example

Example consumer contract demonstrating the on-chain pull pattern: call the Pull Verifier via a cross-contract call (Promise) and read the verified price in a callback.

**Not audited — for integration reference and end-to-end testing only.**

## Build

```bash
just build-consumer
```

## Test

```bash
just test-consumer
```

## Key Files

- `src/ext.rs` — self-contained cross-contract interface (`FeedData` + `#[ext_contract]` trait). Copy this file into your own project to integrate with the verifier.
- `src/lib.rs` — consumer contract logic (cross-contract call + callback + storage).
