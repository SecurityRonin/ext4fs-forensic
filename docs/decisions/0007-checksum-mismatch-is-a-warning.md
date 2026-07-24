# 7. Checksum mismatches are non-fatal observations, not parse errors

Date: 2026-07-24
Status: Accepted

## Context

ext4 protects the superblock, group descriptors, and inodes with CRC32C
(Castagnoli) checksums matching the Linux kernel's `crc32c_le()`. A general
filesystem driver treats a bad checksum as corruption and refuses to mount. A
*forensic* reader faces the opposite requirement: damaged, partially-overwritten,
or deliberately-tampered filesystems are precisely the images it must still parse
and report on. Aborting on a checksum failure would throw away the evidence.

## Decision

Parse structures regardless of checksum validity, and expose checksum
verification as a **separate, non-fatal boolean check** rather than folding it
into the parse result:

- `Superblock::verify_checksum(&self, raw_buf) -> bool`
  (`ext4fs-core/src/ondisk/superblock.rs`) recomputes CRC32C and reports the
  match without failing the parse.
- The CRC32C algorithm is implemented to match the kernel's `crc32c_le()`
  (`ondisk/superblock.rs`), so a "mismatch" reflects the disk, not our arithmetic.
- Cross-structure divergence is surfaced as a graded `EXT4-*` finding (e.g.
  superblock-backup comparison in `forensic/superblock_verify.rs` → the
  findings adapter, ADR 0002), phrased as a consistency anomaly "consistent with"
  a resize/`tune2fs` edit/corruption/tampering — never "tamper detected".

## Consequences

- The reader serves corrupted and tampered images instead of refusing them —
  the forensic use case that motivates the whole tool.
- Checksum status is available to callers as data to reason about, not an
  exception that halts analysis; the examiner decides what a mismatch means.
- This is the deliberate exception to fail-loud: a *checksum* mismatch is
  expected, in-band evidence to be reported, not a bootstrap/structural failure
  (which still errors loudly). The README states the posture explicitly.
