# 1. Publish the reader as `ext4fs-core`, keep the `use ext4fs` import path

Date: 2026-07-24
Status: Accepted

## Context

The repo is `ext4fs-forensic`, and the natural crate name for the reader is the
bare `ext4fs`. That name is already taken on crates.io by an unrelated
third-party crate (`yybit`'s `ext4fs`), so it cannot be claimed. The fleet crate
naming grammar (`~/src/ronin-issen/CLAUDE.md` → "Crate naming grammar") covers
exactly this: when the bare name is taken by a crate we can co-exist with,
publish under a `-core` package but keep the ergonomic import path via a `[lib]
name` override (the vmdk-core / ntfs-core precedent).

The rename happened after initial development — the git history records it as a
deliberate two-step: `76a7376 refactor(naming): publish reader as ext4fs-core
(lib name ext4fs)` and `638f1af fix(naming): complete ext4fs-core rename in
manifest + lockfile`.

## Decision

Publish the reader crate as **`ext4fs-core`** with `[lib] name = "ext4fs"`
(`ext4fs-core/Cargo.toml`), so downstream code still writes `use ext4fs::…`.
The workspace declares the inter-crate dependency once as
`ext4fs = { package = "ext4fs-core", path = "ext4fs-core", version = "0.2.6" }`
(`Cargo.toml [workspace.dependencies]`), and both binary members depend on
`ext4fs = { workspace = true }`.

## Consequences

- The crates.io package name is unambiguous and self-describing ("the core of
  the ext4fs-forensic suite"); the import path stays short and idiomatic.
- No hijack of the popular-name namespace: we co-exist with the existing
  `ext4fs` crate rather than shadowing it.
- The package-vs-lib-name split is invisible to consumers but must be kept in
  sync in every manifest and the lockfile (the second rename commit existed only
  to finish propagating it).
