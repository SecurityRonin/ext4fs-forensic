# Task Completion Checklist

1. `cargo fmt --all`
2. `cargo clippy --all-targets`
3. `cargo test -p ext4fs`
4. Verify no warnings

## TDD (Mandatory)
1. RED: Write failing test
2. GREEN: Minimal implementation
3. REFACTOR: Clean up, tests stay green

## Notes
- Never run multiple test processes concurrently
- Prefer targeted test runs
- Only commit when user explicitly asks
