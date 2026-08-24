# ext4fs-forensic

Forensic analyzer over the [`ext4fs-core`](../ext4fs-core) ext4 reader. Emits graded
[`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) observations grounded in the
filesystem's own on-disk state — each an observation (“consistent with”), never a conclusion.

## Findings

| code | severity | what it observes |
|---|---|---|
| `EXT4-INODE-DELETED` | Info | A deleted inode (`dtime` set). Carries the reader's recoverability estimate (share of data blocks still unallocated); on ext4 the extent tree is usually cleared on delete, so 0% still evidences the deletion via surviving metadata. |
| `EXT4-DELETED-BUT-LINKED` | Medium | An inode stamped with a deletion time (`dtime ≠ 0`) while still linked (`links_count > 0`) — a contradiction, since deletion zeroes the link count. Consistent with an undelete that did not clear `dtime`, tampering, or corruption. |

## Validation

Tier-2 against the repo's committed e2fsprogs images (`tests/data/`): the clean `minimal.img` yields
**zero** findings (a false positive is a failing test), and `forensic.img` — which deleted two files
before unmount — surfaces its deleted inodes while tripping no deleted-but-linked contradiction (a
true negative on an image that genuinely contains deletions). The deleted-but-linked predicate is
graded directly as a positive control.

Part of the [`ext4fs-forensic`](https://github.com/SecurityRonin/ext4fs-forensic) workspace. Every
parser in the fleet is a reader (`-core`) plus an analyzer (`-forensic`), per ADR-0008/0009.
