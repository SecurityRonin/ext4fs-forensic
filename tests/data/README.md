# `ext4fs-forensic` test fixtures

Per-file provenance for the committed test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) (§C3 for these
ext4 images) — this README is the co-located human detail; cross-reference, never duplicate.
The evidence-tier analysis of what each image validates lives in
[`../../docs/validation.md`](../../docs/validation.md); it is not repeated here.

`tests/data/` here is **not** gitignored (`.gitignore` is just `/target/`), so these small
fixtures are committed. They live at the **repo root** `tests/data/`; each workspace member's
tests reach them via the relative path `concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/<file>")`.

**These are self-minted images, not real-world evidence.** Both `.img` files are produced by
this repo's own scripts using `mkfs.ext4` (e2fsprogs) — they are real e2fsprogs output (so
format-level parsing against them is independently grounded), but the forensic-recovery ground
truth (which inodes/filenames were deleted) is recorded by the same script that built the image,
not by an independent third party. See `docs/validation.md` for the per-capability tier.

#### minimal.img

- **Source / Identity:** self-minted 4 MiB ext4 image (`extents`, `metadata_csum`, `64bit`,
  `extra_isize`; 4096-byte blocks; label `test-ext4`). Contains `hello.txt` ("Hello, ext4!",
  inode 12) and `subdir/nested.txt` ("Nested file"). No journal.
- **Generator (verbatim):** `tests/create-minimal-image.sh` — requires Linux + root, runs:

  ```sh
  dd if=/dev/zero of=minimal.img bs=1M count=4
  mkfs.ext4 -F -b 4096 -O extents,metadata_csum,64bit,extra_isize -L "test-ext4" minimal.img
  # mount -o loop, write hello.txt + subdir/nested.txt, umount
  ```

- **Used by:** the `minimal.img` arms of `ext4fs-core` unit tests — superblock parsing
  (`ondisk/superblock.rs`), block/dir/inode reads (`block.rs`, `dir.rs`, `inode.rs`),
  no-journal skip paths (`forensic/journal.rs`), slack/carving/timeline/xattr/deleted
  baselines (`forensic/*.rs`).
- **License / redistribution:** self-minted by this repo's Apache-2.0 build; repo-internal,
  no third-party rights. **Self-minted `mkfs.ext4` image — NOT a real-world forensic image.**

#### forensic.img

- **Source / Identity:** self-minted 32 MiB ext4 image with journal (`has_journal`,
  `metadata_csum`, `64bit`, `extents`; 4096-byte blocks; label `forensic-test`). Contains
  regular files (`hello.txt` "Hello, forensic world!" inode 12, `hello2.txt`, `subdir/nested.txt`),
  symlinks (absolute `abs-link`, relative `rel-link`, multi-component `deep-link`, `../`-relative
  `linkdir/up-link`), `user.*` extended attributes on `hello.txt` (`user.forensic`=evidence-tag,
  `user.case_id`=2026-0401), and two files that were **created then deleted** to leave
  recoverable artifacts (`deleted-file.txt`, multi-block `deleted-large.txt`).
- **Generator (verbatim):** `tests/create-forensic-img.sh` — requires Docker (privileged
  `debian:bookworm-slim` + e2fsprogs + attr), runs:

  ```sh
  dd if=/dev/zero of=forensic.img bs=1M count=32
  mkfs.ext4 -F -L forensic-test -O has_journal,metadata_csum,64bit,extents -b 4096 forensic.img
  # mount -o loop; write regular files, symlinks, setfattr xattrs;
  # write deleted-file.txt + deleted-large.txt, record their inode numbers,
  # then rm both; sync; umount; copy image out
  ```

- **Used by:** the `forensic.img` arms across `ext4fs-core` (`inode.rs`, `dir.rs`, `lib.rs`,
  `ondisk/{inode,group_desc}.rs`, `forensic/{superblock_verify,recovery,journal,timeline,
  carving,slack,history,search,xattr,deleted,hash,dir_recovery}.rs`), `ext4fs-fuse`
  (`main.rs`), and `ext4fs-cli` (`mcp.rs`).
- **License / redistribution:** self-minted by this repo's Apache-2.0 build; repo-internal,
  no third-party rights. **Self-minted `mkfs.ext4` image — NOT a real-world forensic image.**

#### deleted-ino.txt

- **Source / Identity:** the generator's **self-recorded answer key** for `forensic.img` —
  the two inode numbers (`21`, `22`) of `deleted-file.txt` and `deleted-large.txt`, captured by
  `tests/create-forensic-img.sh` via `stat -c "%i"` **before** it deleted those files.
- **Generator (verbatim):** written inside `tests/create-forensic-img.sh`:

  ```sh
  stat -c "%i" $MNT/deleted-file.txt  > /out/deleted-ino.txt
  stat -c "%i" $MNT/deleted-large.txt >> /out/deleted-ino.txt
  ```

- **Used by:** the deleted-inode recovery tests (`forensic/deleted.rs`, `forensic/recovery.rs`)
  as the expected-inode ground truth.
- **Caveat:** because the same script both deletes the files and records this key, it is **Tier 3**
  (self-authored ground truth) — an independent recovery oracle (e.g. The Sleuth Kit `fls -d`,
  `ext4magic`, `extundelete`) is recommended to lift this to Tier 1. See `docs/validation.md`.
- **License / redistribution:** self-minted; repo-internal, Apache-2.0.

#### inline.img

- **Source / Identity:** self-minted 1 MiB ext4 image with the `inline_data` feature
  (`inline_data`, `extent`; 256-byte inodes; 1024-byte blocks). Contains a single small
  regular file `inlinefile` ("inline!", inode 12) whose 7 data bytes live **inside the
  inode body** (INLINE_DATA flag `0x1000_0000`), never in a data block.
- **Generator (verbatim):** minted on macOS with Homebrew e2fsprogs (`mke2fs` + `debugfs`,
  no root/loop mount needed):

  ```sh
  dd if=/dev/zero of=inline.img bs=1024 count=1024
  mke2fs -q -t ext4 -O inline_data,extent -I 256 -b 1024 -F inline.img
  printf 'inline!' > inl.txt
  debugfs -w -R "write inl.txt inlinefile" inline.img
  ```

- **Used by:** `ext4fs-core/tests/vfs_ext4.rs::meta_of_inline_file_is_resident` — proves the
  forensic-vfs adapter reports `ResidencyKind::Resident { inline_len }` for an inline file.
- **License / redistribution:** self-minted by this repo's Apache-2.0 build; repo-internal,
  no third-party rights. **Self-minted e2fsprogs image — NOT a real-world forensic image.**

#### ext2-128.img

- **Source / Identity:** self-minted 512 KiB **ext2** image with **128-byte inodes**
  (`-I 128`; 1024-byte blocks). 128-byte inodes predate the extended-timestamp fields
  (`extra_isize < 28`), so they carry no `crtime` and only second-resolution timestamps.
  Contains a single regular file `afile` (inode 12).
- **Generator (verbatim):** minted on macOS with Homebrew e2fsprogs:

  ```sh
  dd if=/dev/zero of=smallinode.img bs=1024 count=512
  mke2fs -q -t ext2 -I 128 -b 1024 -F smallinode.img   # committed as ext2-128.img
  printf 'small-inode file\n' > sf.txt
  debugfs -w -R "write sf.txt afile" ext2-128.img
  ```

- **Used by:** `ext4fs-core/tests/vfs_ext4.rs::meta_of_128_byte_inode_has_no_born_time` —
  proves the adapter emits `born: None` (crtime absent) and seconds resolution on a
  128-byte inode.
- **License / redistribution:** self-minted by this repo's Apache-2.0 build; repo-internal,
  no third-party rights. **Self-minted e2fsprogs image — NOT a real-world forensic image.**

## MD5 manifest

| File | Bytes | MD5 |
|---|---|---|
| `minimal.img` | 4194304 | `966b3e52d95cb84679a973f43fd3702e` |
| `forensic.img` | 33554432 | `78ed02d781e1b589b5bd6037bdb44055` |
| `deleted-ino.txt` | 6 | `6cf8c3f94aac46bfc22821c9b1ef86dd` |
| `inline.img` | 1048576 | `70b54a304d67fdf2d175d004ff3b2060` |
| `ext2-128.img` | 524288 | `e62803f6f3969a954dcbdda63810b372` |
