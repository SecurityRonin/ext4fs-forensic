# 5. Endianness: ext4 structures little-endian, jbd2 journal big-endian

Date: 2026-07-24
Status: Accepted

## Context

ext4 on-disk structures (superblock, group descriptors, inodes, extents,
directory entries) are stored **little-endian**. The jbd2 journal that ext4 uses
for metadata journaling is a separate on-disk format inherited from JBD, and its
headers and descriptor blocks are **big-endian**. A parser that assumes one
endianness for the whole image silently misreads the other half — a classic
source of inverted fields that pass shallow tests.

This is a documented property of the formats (kernel.org ext4 / jbd2
documentation), not a choice, but *handling both correctly* is a load-bearing
implementation decision that must be recorded so a future contributor does not
"normalize" one path to the other.

## Decision

Parse ext4 structures little-endian and jbd2 journal structures big-endian, each
through the appropriate `safe-read` accessor:

- ext4 side uses little-endian reads — e.g. `u32::from_le_bytes([...])` helpers
  in `ondisk/superblock.rs`.
- journal side uses big-endian reads — e.g. `safe_read::be_u32(buf, ...)`
  throughout `ondisk/journal.rs`, whose field table is annotated "Offsets (all
  big-endian)".

## Consequences

- Journal transactions, commit sequences, and revoked-block records decode
  correctly rather than as byte-swapped garbage.
- The endianness of each field is fixed by which module reads it; mixing an ext4
  reader into the journal path (or vice versa) is a bug the module boundary makes
  visible.
- The distinction is called out in the README ("ext4 is little-endian, jbd2
  journal is big-endian — both handled correctly") so it is discoverable outside
  the code.
