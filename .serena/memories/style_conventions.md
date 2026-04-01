# Code Style & Conventions

- `#![forbid(unsafe_code)]` — pure safe Rust
- Edition 2021, standard Rust naming (`snake_case` fns, `PascalCase` types)
- Doc comments (`///`) on public API items
- Unified `Ext4Error` enum with `Result<T>` alias; use `?` operator, no `.unwrap()` in lib
- Checksum mismatches are warnings (forensic tolerance)
- On-disk structs parsed from `&[u8]` with explicit field extraction
- Little-endian ext4, big-endian jbd2
- `bitflags` for flag fields, CRC32C for metadata verification
- `ondisk/` = raw structs only; layers compose via ownership
- `forensic/` submodules: deleted, journal, recovery, timeline, xattr, carving
- Tests use `Cursor<Vec<u8>>` with test images, graceful skip if absent
