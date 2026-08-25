# 8. Lean core with optional integration features (`ewf`, `vfs`, `hashing` via `blazehash-core`)

Date: 2026-07-24
Status: Accepted

## Context

`ext4fs-core` is both an end-user forensic tool (via the CLI/MCP/FUSE members)
and a library other fleet crates may link. The fleet's batteries-included rule
says a shipping *binary* must compile every capability in, while the fleet's
lean-`-core` rule says a library others link should stay dependency-light so it
does not drag a heavy or license-tainted transitive tree onto every consumer. The
resolution is the split: keep the core lean, let the binaries turn features on.

Concretely, three integrations each carry weight that not every consumer wants:
EWF/E01 support (`ewf` crate), file hashing (the full `blazehash` app pulls an
`opendal`/cloud stack), and the forensic-vfs `FileSystem` adapter
(`forensic-vfs` KNOWLEDGE leaf). The reader itself only needs a `Read + Seek`
source (ADR 0003).

## Decision

Gate integrations behind Cargo features (`ext4fs-core/Cargo.toml`):

- `default = ["hashing"]` — file hashing on by default, backed by
  **`blazehash-core`** (the lean hash-primitives library), imported as
  `blazehash` via the package rename. Explicitly *not* the full `blazehash` app,
  to avoid its license-tainted cloud transitive tree (`7beb8a1 chore(deps): lean
  blazehash-core + green cargo-deny`).
- `ewf = ["dep:ewf"]` — optional E01/EWF source support (`Ext4Fs::open_ewf`,
  `core/src/lib.rs`), added in `b7ac828`.
- `vfs = ["dep:forensic-vfs"]` — optional `impl FileSystem for Ext4Fs`
  (`core/src/vfs.rs`) so an ext4 volume composes as `Arc<dyn FileSystem>`
  in the forensic-vfs engine (`634d527`).

The binary members compile the capabilities they need in; a library consumer
opts into only what it links.

## Consequences

- A library consumer gets a lean reader (hashing, no cloud stack; EWF and VFS
  only if asked), keeping `cargo deny` green and the transitive tree small.
- The reader stays source-agnostic: raw files always, EWF and forensic-vfs
  composition behind one feature flag each.
- `forensic-vfs` is pinned to a moving major (0.3 → 0.4 → 0.5 → 0.7 across the
  history) — an accepted maintenance cost of tracking the evolving contract crate,
  visible in commits `e54b891`/`06f5dfd`/`31aeb09`/`9cd2f86`.
- Tension with strict batteries-included is deliberate: the *lean library core /
  full binary* split is the fleet's sanctioned mechanism, and this is its
  application to ext4fs.
