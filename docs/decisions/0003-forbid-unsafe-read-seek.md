# 3. `#![forbid(unsafe_code)]`: pure-safe-Rust parsing over a `Read + Seek` block abstraction

Date: 2026-07-24
Status: Accepted

## Context

These crates parse untrusted, attacker-controllable disk images, so the memory
model is a security boundary. The fleet's `unsafe`-exception law makes
`forbid(unsafe)` the default *and the goal* — a provable, badge-able "zero places
a crafted input can corrupt memory" — and only downgrades to `deny` + a bounded
per-site `#[allow]` when a real benefit (e.g. an `mmap` scanner in `ewf` /
`memory-forensic`) justifies surrendering the compiler's proof.

ext4fs has no such justification. It reads the image through a `Read + Seek`
block abstraction (`BlockReader` over any source), not a memory map — see
`Ext4Fs<R: Read + Seek>` (`core/src/lib.rs`) and `block.rs`. Nothing in
the parser needs raw pointers or `get_unchecked`; integer field reads route
through the `safe-read` crate (ADR 0004). So the crate can hold the strongest
posture at zero cost.

## Decision

Adopt **`unsafe_code = "forbid"`** at the workspace level
(`Cargo.toml [workspace.lints.rust]`) and `#![forbid(unsafe_code)]` at each
crate root (`core/src/lib.rs`, `core/src/forensic/mod.rs`,
`cli/src/main.rs`, `cli/src/mcp.rs`). Accept **any `Read + Seek`
source** — raw image, EWF/E01 (via the `ewf` feature, ADR 0008), or a custom
reader — rather than an `mmap`, so the forbid holds.

## Consequences

- `rg 'allow(unsafe_code)'` returns nothing: the crate is genuinely
  unsafe-free, not `deny` + allows, so it can wear the `unsafe-forbidden` badge
  honestly (unlike the mmap crates, which skip it).
- No C bindings, no FFI liability, no `-sys` chain — a pure-Rust dependency
  posture that eases embedding in commercial and court-facing toolchains.
- `Read + Seek` costs positioned reads instead of zero-copy slices into a mapped
  file; for a forensic reader this is a fully acceptable trade for the safety
  proof.
