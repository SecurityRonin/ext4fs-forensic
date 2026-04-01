# Suggested Commands

## Build
```bash
cargo build                    # Build all
cargo build -p ext4fs          # Build library only
```

## Test
```bash
cargo test -p ext4fs           # All tests
cargo test -p ext4fs -- --nocapture  # With stdout
cargo test -p ext4fs <name>    # Specific test
```

## Lint & Format
```bash
cargo fmt --all                # Format
cargo fmt --all -- --check     # Check only
cargo clippy --all-targets     # Lint
```

## Test Images
```bash
bash tests/create-forensic-img.sh   # Create test images (Linux/Docker)
```
