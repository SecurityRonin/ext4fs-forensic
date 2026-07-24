# 4. Panic-free parsing of untrusted images: `safe-read`, denied unwrap/expect, cargo-fuzz

Date: 2026-07-24
Status: Accepted

## Context

An ext4 image is untrusted input. A length field, offset, or count read from the
image can be malformed or adversarial; a hand-rolled
`from_le_bytes(..).try_into().unwrap()` slice read panics on a short buffer, and
some `data.get(off..off+4)` variants can overflow `usize`. The fleet's Paranoid
Gatekeeper standard requires these parsers to *never panic, never read out of
bounds, never trust a length field*, and mandates the single audited bounds-checked
reader (`safe-read`) rather than a per-crate `bytes.rs`.

The history shows this was hardened over time, not assumed: `dffb9ae test(RED):
fuzz targets for ext4fs parse_superblock, parse_inode, read_dir` then the GREEN
fixes `55c241d`/`d0eae8f`/`a488fb0` (validate `log_block_size` / `desc_size` /
GDT size before shifting or allocating), and later `7c0bcf5 fix(ext4fs-core):
panic-free reader + enforce unwrap/expect deny` plus `dd34afe test(journal): RED
— parse_v3 must fail loud on truncated tag`.

## Decision

1. **Bounds-checked integer reads via `safe-read`** (`ext4fs-core/Cargo.toml`:
   `safe-read = "0.1"`) — reads return 0 out of range instead of panicking;
   used throughout `ondisk/` (e.g. `safe_read::be_u32(buf, 0)` in
   `ondisk/journal.rs`). This replaces hand-rolled unwrap-on-slice reads.
2. **Deny the panic lints workspace-wide** —
   `unwrap_used = "deny"` and `expect_used = "deny"`
   (`Cargo.toml [workspace.lints.clippy]`); test modules re-allow them via
   `#![cfg_attr(test, allow(...))]` at each crate root.
3. **cargo-fuzz target per parsed structure** — `fuzz/fuzz_targets/`:
   `parse_superblock`, `parse_inode`, `read_dir`, wired into CI by
   `6fdc06a ci(fuzz)`.
4. **Fail loud on truncation**, not silent wrong output — e.g. the journal v3 tag
   parser rejects a truncated tag rather than fabricating a record.

## Consequences

- Malformed images degrade gracefully or error explicitly; they do not crash the
  CLI, the MCP server, or a FUSE mount, and they do not silently emit fabricated
  structure.
- The static (deny lints) and dynamic (fuzz) halves are complementary: the lints
  make panics unreachable by construction, the fuzzer tests that empirically —
  the README leads with the measured "input-fuzzed" claim and qualifies the
  static "panic-free by lint" posture beside it (fleet robustness-wording rule).
- Some length/offset/count checks (allocation caps, structural validation) remain
  the reader's own job; `safe-read` only covers fixed-width field reads.
