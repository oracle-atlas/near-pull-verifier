# Pull Oracle Verifier — task runner
# Run `just` (or `just --list`) to see available recipes.

# Path to the deployable wasm produced by `cargo near build`.
wasm := "target/near/pull_verifier.wasm"

# Type-check the contract for the wasm target (fast, no artifact).
check:
    cargo check --target wasm32-unknown-unknown

# Run all tests (unit + sandbox integration).
test:
    cargo test

# Development build (fast, non-reproducible). Produces {{wasm}}.
build:
    cargo near build non-reproducible-wasm

# Production build (reproducible, via Docker; requires committed git state).
build-release:
    cargo near build reproducible-wasm

# Show the deployable wasm size in bytes (this is the on-chain contract size).
# Runs a fresh dev build first so the number reflects current code.
size: build
    @echo "{{wasm}}: $(stat -f%z {{wasm}}) bytes"

# Show the wasm size without rebuilding (uses the existing artifact).
size-only:
    @test -f {{wasm}} || (echo "No wasm found — run 'just build' first" && exit 1)
    @echo "{{wasm}}: $(stat -f%z {{wasm}}) bytes"

# Remove build artifacts.
clean:
    cargo clean
