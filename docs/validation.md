# Validation

`ext4fs-forensic` parses untrusted ext4 structures from potentially compromised
disk images. Correctness for forensic tooling is established against
**independent oracles** (a different tool, or a different code path, that already
decodes the same bytes correctly) on data with known ground truth — never against
fixtures we hand-encoded and then graded ourselves.

This page records, accurately, which checks back each capability today and at
what evidence tier — including where an independent oracle is *recommended but
not yet wired*. It is a trust document: every oracle and corpus named below has a
concrete `file:line` citation in this repository, and capabilities validated only
against self-minted fixtures are labelled as such.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Current state in one line

The on-disk readers (superblock, group descriptor, inode) are validated at
**Tier 2** because the test images were produced by **`mkfs.ext4` (e2fsprogs)**
and the Linux kernel mount path — independent code wrote the metadata and the
CRC32C checksums, and the crate parses/recomputes them independently. The
forensic recovery capabilities (deleted inodes, directory-entry recovery,
journal, timeline, slack, xattrs, symlinks) are currently validated at **Tier 3**
against fixtures this repository itself generates, with ground truth taken from
the generator script's own bookkeeping. An independent differential oracle
(`debugfs` / `dumpe2fs` / The Sleuth Kit) is **recommended but not yet wired**
into the test suite — see [Gaps](#gaps-honest-caveats).

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **`mkfs.ext4` (e2fsprogs)** + Linux kernel mount path | Yes — separate C codebase that authored the image metadata and CRC32C checksums | Superblock / group-descriptor / inode fields and their on-disk CRC32C checksums recompute correctly | 2 |
| **`crc` crate** (CRC32C, ISO 3309 / Castagnoli) | Yes — vetted third-party checksum crate we reuse | The CRC32C computation itself | 1 |

The CRC32C cross-check is the load-bearing independent element: e2fsprogs wrote
each checksum; `ext4fs-core` independently recomputes it with a third-party `crc`
implementation and requires a match (`group_desc.rs:240` `gd.verify_checksum(...)`,
`inode.rs:518` `inode.verify_checksum(...)`). A bit-flip in our field offsets or seed handling
would fail the checksum, so the metadata layout is checked against a value we did
not author.

### Oracle gap (recommended, not yet wired)

`debugfs` / `dumpe2fs` (e2fsprogs) and The Sleuth Kit (`fls`, `istat`, `icat`)
are the established independent ext4 oracles. This repo **names e2fsprogs as its
"validation reference"** (README acknowledgments) and uses `debugfs` inside the
`tests/create-minimal-image.sh` generator to *print* reference data for a human
(`tests/create-minimal-image.sh:29-33`), but **no automated test asserts
`ext4fs-forensic` output against `debugfs`/`dumpe2fs`/TSK output**. Wiring such a
differential — especially for deleted-inode recovery and directory-entry recovery
— would lift those capabilities from Tier 3 to Tier 1.

## Test corpora

Both images are **self-minted** by this repository's own scripts using
`mkfs.ext4` and committed under `tests/data/`. There is currently no third-party
real-world corpus and no `tests/data/README.md`; provenance is the generator
scripts themselves.

| Corpus | Source | Used for | License |
|---|---|---|---|
| `minimal.img` (4 MiB) | Self-minted: `tests/create-minimal-image.sh` (`mkfs.ext4 -b 4096 -O extents,metadata_csum,64bit,extra_isize -L test-ext4`) | Superblock parse, block/dir reader, journal, timeline | Repo-internal (Apache-2.0) |
| `forensic.img` (32 MiB) | Self-minted: `tests/create-forensic-img.sh` (Docker `debian:bookworm-slim` → `mkfs.ext4 -O has_journal,metadata_csum,64bit,extents`; writes files, symlinks, xattrs, then deletes inodes 21/22) | Group-descriptor + inode CRC32C verify, deleted-inode recovery, dir-entry recovery, journal, xattrs, symlinks, slack | Repo-internal (Apache-2.0) |
| `deleted-ino.txt` | Self-minted: recorded by `create-forensic-img.sh` before deletion (`21`, `22`) | Ground-truth inode numbers for deleted-file recovery tests | Repo-internal (Apache-2.0) |

Because the generator both writes the bytes and records the answer key, the
forensic-recovery ground truth is **not independent** — it is Tier 3. The images
are real `mkfs.ext4` output, so the *format-level* parse against them is Tier 2;
the *recovery answers* are self-authored.

## Per-capability validation

### Superblock parsing — Tier 2

`ext4fs-core/src/ondisk/superblock.rs:479` (`parse_from_minimal_image`) parses
the superblock from the real `mkfs.ext4`-produced `minimal.img` and asserts
magic `0xEF53`, 4096-byte blocks, label `test-ext4`, and the extents /
metadata_csum / 64bit feature flags — fields written by e2fsprogs, not by us.

### Group-descriptor CRC32C — Tier 2

`ext4fs-core/src/ondisk/group_desc.rs:216` (`verify_group_descriptor_checksum_on_forensic_img`)
recomputes the group-descriptor CRC32C over the on-disk bytes from `forensic.img`
and requires it to match the checksum e2fsprogs wrote.

### Inode CRC32C — Tier 2

`ext4fs-core/src/ondisk/inode.rs:481` (`verify_inode_checksum_on_forensic_img`)
recomputes the inode CRC32C against the value written by e2fsprogs on
`forensic.img`.

### Deleted-inode recovery — Tier 3 (independent oracle recommended)

`ext4fs-core/src/forensic/recovery.rs:176,193`
(`recover_deleted_inode_21_hits_zero_size_path`,
`recover_deleted_inode_22_hits_zero_size_path`) exercise recovery against inodes
the generator itself deleted (`deleted-ino.txt` = 21, 22). The answer key is
self-authored. A `debugfs`/TSK differential is the recommended upgrade.

### Directory-entry (deleted filename) recovery — Tier 3

`ext4fs-core/src/forensic/dir_recovery.rs:120,127` drive
`recover_dir_entries` over `forensic.img` / `minimal.img`. Ground truth is the
file set the generator wrote; not independently confirmed.

### jbd2 journal parsing — Tier 3

`ext4fs-core/src/forensic/journal.rs:269,327` parse the journal from
`minimal.img` / `forensic.img` and assert structural invariants (block size > 0,
non-empty transactions, monotonic sequence at `:388`). The corrupt-input tests
(`:477,520,572`) confirm malformed journals fail loudly rather than producing
wrong output. Invariants are checked; record contents are not differenced against
an external journal decoder.

### Timeline, slack, xattrs, symlinks — Tier 3

`forensic/timeline.rs:117,139` (event types, sorting, deletion events),
`forensic/slack.rs:110,151` (slack offset + length invariants),
`forensic/xattr.rs:120,139` (xattrs written by the generator), and the symlink
fixtures from `create-forensic-img.sh` are exercised against self-minted data
with self-authored expectations.

### Robustness — never panic, never over-read — Tier 2

The bounds-checked parsers reject short/truncated input
(`group_desc.rs` `reject_too_short`, journal corrupt-input tests above) with
typed `Ext4Error`s rather than panicking. `unsafe_code = "forbid"`
(`Cargo.toml:29`) is enforced workspace-wide, and `correctness` / `suspicious`
clippy lints are `deny` (`Cargo.toml:33-34`). cargo-fuzz targets exist for the
highest-risk parsers (`fuzz/fuzz_targets/parse_superblock.rs`,
`parse_inode.rs`, `read_dir.rs`); their invariant is "must not panic."

## Reproducing the validation

All tests are committed inline `#[cfg(test)]` modules and run with `cargo test`.
The image-backed tests **skip cleanly** when the fixture is absent (they print
`skip: …`), so a checkout without the images still passes; regenerate the images
with the scripts below to exercise them.

```bash
# Full suite (image-backed tests skip if fixtures absent)
cargo test --workspace

# Regenerate the fixtures (Linux; forensic.img needs Docker)
bash tests/create-minimal-image.sh      # -> tests/data/minimal.img  (mkfs.ext4 + debugfs)
bash tests/create-forensic-img.sh       # -> tests/data/forensic.img (Docker e2fsprogs)

# Targeted format-level (Tier 2) checks against mkfs.ext4 output
cargo test -p ext4fs-core parse_from_minimal_image
cargo test -p ext4fs-core verify_group_descriptor_checksum_on_forensic_img
cargo test -p ext4fs-core verify_inode_checksum_on_forensic_img

# Targeted forensic-recovery (Tier 3) checks
cargo test -p ext4fs-core recover_deleted_inode_21_hits_zero_size_path
cargo test -p ext4fs-core parse_journal_from_forensic
```

Fuzz a parser locally (requires `cargo install cargo-fuzz` + nightly):

```bash
cargo +nightly fuzz run parse_superblock
cargo +nightly fuzz run parse_inode
cargo +nightly fuzz run read_dir
```

## CI gates as backstops

The CI workflow (`.github/workflows/ci.yml`) enforces `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo-deny`, and a
gitleaks secret scan on every PR. Two backstops common elsewhere in the fleet are
**not yet wired here** and are tracked as gaps below:

- **Line-coverage gate** — there is no `cargo llvm-cov` job in CI. The README's
  coverage figures are a one-time local measurement, not an enforced gate.
- **Fuzz CI** — fuzz targets exist but there is no `fuzz.yml` building/smoke-running
  them in CI.

## Finding adapter (`forensic::findings`) — TSK cross-check

The `forensic::findings` module is a thin
[`forensicnomicon::report::Observation`] adapter: it performs **no new parsing**,
only surfaces what the engine already computes as graded `EXT4-*` findings.
Because it re-uses the engine outputs, its correctness reduces to (a) the engine
output it adapts and (b) the mapping. The engine output is cross-checked against
**The Sleuth Kit** (`fls`/`istat`/`fsstat`/`jls`, all installed) on the real
`tests/data/forensic.img`; the mapping is asserted in
`ext4fs-core/src/forensic/findings.rs` (`mod tests`).

| `EXT4-*` code | Engine module | Severity / Category | TSK oracle (Tier 2) |
|---|---|---|---|
| `EXT4-SUPERBLOCK-BACKUP-MISMATCH` | `superblock_verify` | Medium / Integrity | `fsstat` — `Number of Block Groups: 1`, so there are **no** backup superblocks; the adapter correctly emits zero findings (empty result, not a bootstrap failure) |
| `EXT4-DELETED-INODE` | `deleted` | Medium (recoverable) / Residue | `fls -rd forensic.img` → deleted inodes **21** and **22**; `istat` confirms both `Not Allocated`, `Deleted:` time set, `links 0`. The adapter's deleted set contains 21 and 22 |
| `EXT4-SLACK-RESIDUE` | `slack` | Low / Residue | engine `scan_all_slack`; the adapter emits a finding only for blocks whose slack has ≥1 non-zero byte (each asserted `nonzero_bytes > 0`) |
| `EXT4-JOURNAL-INCONSISTENT` | `journal` | Medium / History | see methodology note below |

**Cross-check commands (reproducible):**

```
fsstat forensic.img | grep 'Number of Block Groups'   # => 1  (no SB backups)
fls -rd forensic.img                                  # => deleted inodes 21, 22
istat forensic.img 21 ; istat forensic.img 22         # => Not Allocated, Deleted set
```

**Journal methodology note (honest, Tier 2).** `EXT4-JOURNAL-INCONSISTENT`
surfaces a commit-timestamp *regression*: jbd2 commits in increasing sequence
order, so a committed transaction whose commit instant precedes an earlier one's
is replay-relevant. On `forensic.img` the **engine** parses two committed
transactions — seq 2 @ `1774998586.843380012`, seq 3 @ `1774998586.873380012`
(monotonic at full precision), so the adapter emits **zero** journal findings,
the correct clean result. TSK `jls` additionally lists *stale/recycled* commit
blocks in the circular journal (seq 2 @ `…586.446`, seq 3 @ `…586.149`) that the
engine does not treat as committed transactions; this is a difference in what
each tool counts as a transaction, not a decode disagreement. The
regression-detection path itself is exercised by a synthetic transaction stream
(`journal_findings_flag_timestamp_regression`), with the monotonic real-image
case asserted separately (`real_image_journal_is_monotonic_so_no_findings`).

All four mappings assert the derived **code/category/severity** and the
"consistent with" note framing (no verdict language); a superblock-backup
divergence in particular is graded as a consistency anomaly (Medium), not "tamper
detected", since it has benign causes (a resize that did not propagate, a
`tune2fs` edit).

## Gaps (honest caveats)

1. **The deleted-inode / superblock / journal findings are now cross-checked
   against The Sleuth Kit** on the real image (Tier 2, see the section above);
   forensic-recovery *content* ground truth (e.g. carved file bytes) remains
   self-authored (Tier 3). `debugfs` / `dumpe2fs` differential oracles are still
   recommended for the recovery code paths.
2. **No third-party real-world corpus.** Both images are self-minted by this
   repo; there is no public, independently-ground-truthed ext4 corpus (e.g. a
   DFIR CTF Linux image) in the suite yet, and no `tests/data/README.md` /
   per-file provenance entry.
3. **No coverage or fuzz CI gate** (see above).

Per-file provenance lives in the generator scripts (`tests/create-minimal-image.sh`,
`tests/create-forensic-img.sh`); the fleet-wide machine index is
`issen/docs/corpus-catalog.md`.
