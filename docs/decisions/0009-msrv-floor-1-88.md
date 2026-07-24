# 9. MSRV floor pinned at 1.88, workspace-inherited, below the dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet separates the **dev toolchain** (pinned in `rust-toolchain.toml`, here
`1.96.0`, the current stable) from the **declared MSRV** (`rust-version`, a
downstream-facing compatibility promise). For published libraries the fleet keeps
a low, CI-verified MSRV (typically `1.75`/`1.80`). `ext4fs-core` is a published
library, so it declares an MSRV rather than pinning it to the dev toolchain — but
its floor is **1.88**, above the usual library floor.

## Decision

Declare `rust-version = "1.88"` once at the workspace level
(`Cargo.toml [workspace.package]`) and inherit it in every member via
`rust-version.workspace = true`. The dev toolchain stays at `1.96.0`
(`rust-toolchain.toml`, with `rustfmt` + `clippy` components — `e9090ac`).

## Consequences

- One edit bumps the floor for the whole workspace (DRY), and CI/build honor a
  single number.
- 1.88 is higher than the fleet's usual `1.75`/`1.80` library floor, so the
  crate reaches a narrower audience than a minimal-MSRV library — accepted
  because the floor is set by what the dependency graph actually needs, and the
  fleet rule is to promise only what a library truly requires.

## Unrecovered rationale

The specific reason the floor is **1.88** (rather than the usual `1.75`/`1.80`)
— i.e. which dependency or language feature forced it — is **not recorded in the
available git history or code comments**. Rationale reconstructed from structure;
original intent not recovered in available history. If a later change lowers the
graph's requirement, the floor should be re-verified against a CI MSRV job and
lowered toward the fleet default rather than left stale.
