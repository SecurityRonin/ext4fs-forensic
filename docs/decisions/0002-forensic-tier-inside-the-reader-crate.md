# 2. One reader crate with a two-tier API and a findings adapter, not a separate `-forensic` analyzer crate

Date: 2026-07-24
Status: Accepted

## Context

The fleet's default crate-structure standard for a single-format repo (Pattern A)
is a reader/analyzer split: `<x>-core` (raw reader) + `<x>-forensic` (anomaly
auditor). But that same standard is explicit that `-forensic` is *not required*
to be a separate crate depending on `-core` — forensic examination "often needs
to go much lower level than the `-core` API", so the analyzer may parse the raw
structure directly, and the decision rule is which layout gives the audit the
byte-level access it needs.

For ext4, every forensic operation the tool offers — deleted-inode scanning,
extent-tree recovery of deleted data, jbd2 journal replay, five-timestamp
timeline, slack reads past EOF, superblock-backup comparison, deleted-directory
name recovery — is built on the *same* internal low-level readers as the standard
filesystem access: `BlockReader`, `InodeReader`, and the `ondisk/` byte parsers.
Splitting the forensic ops into a separate crate would force re-exporting all of
that internal machinery across a crate boundary, or re-parsing the image twice.

## Decision

Keep the reader and the forensic operations in **one crate, `ext4fs-core`,
exposed as two tiers of the same `Ext4Fs<R: Read + Seek>` handle**
(`core/src/lib.rs`):

- **Tier 1 — standard access**: `read_file`, `read_dir`, `metadata`.
- **Tier 2 — forensic operations**: the twelve modules under
  `core/src/forensic/` (`deleted`, `recovery`, `journal`, `timeline`,
  `slack`, `search`, `hash`, `history`, `dir_recovery`, `superblock_verify`,
  `carving`, `xattr`), reachable from the same handle.

Fleet-wide reporting is served by a thin **`forensicnomicon::report`
Observation adapter** — `core/src/forensic/findings.rs` — that surfaces
what the engine already computed as graded `EXT4-*` `Finding`s, performing no new
parsing. This lets a `disk-forensic` / Issen orchestrator aggregate ext4 findings
uniformly. The commit pair `e8be6fb`/`f3e6ec1` added it (RED then GREEN).

## Consequences

- The forensic tier reads the raw structure directly through the crate-internal
  readers, exactly the low-level access ADR intent calls for — no anomaly is
  hidden behind a happy-path API, and the image is parsed once.
- There is intentionally **no published `ext4fs-forensic` crate**; the repo name
  reflects the suite's purpose, not a crate. A consumer wanting only the reader
  still gets the whole (still lean) `ext4fs-core`.
- The findings adapter keeps severity/code/note *derived* from each
  classification so they cannot drift, and states anomalies in "consistent with"
  language, never as verdicts (fleet reporting-model rule).
- Trade-off: the crate is larger than a bare reader. Accepted because the
  forensic tier shares the reader's internals; a hard split would duplicate them.
