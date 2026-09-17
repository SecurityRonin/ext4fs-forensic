

#### ext4_xattr.img.gz

- **Source / Identity:** self-minted 16 MiB ext4 image (`extents`, `64bit`;
  4096-byte blocks; **256-byte inodes**; label `XATTRTEST`), built to exercise
  extended attributes across every namespace and BOTH storage forms.
- **Generator (verbatim)** — run in `debian:bookworm-slim` under podman, with
  **no mount**: `debugfs` writes files and attributes directly, so no loop
  device or privileged container is needed.

  ```sh
  dd if=/dev/zero of=ext4_xattr.img bs=1M count=16
  mkfs.ext4 -F -q -L XATTRTEST -O extents,64bit -b 4096 -I 256 ext4_xattr.img
  printf 'hello ext4 xattrs\n' > /tmp/f
  python3 -c "import sys; sys.stdout.write('B'*2000)" > /tmp/big
  debugfs -w ext4_xattr.img <<'EOF'
  write /tmp/f file.txt
  mkdir /adir
  ea_set file.txt user.small tiny-value
  ea_set file.txt user.comment "a second attribute"
  ea_set file.txt security.selinux unconfined_u:object_r:user_home_t:s0
  ea_set file.txt trusted.marker trusted-value
  ea_set -f /tmp/big file.txt user.big
  ea_set /adir user.ondir on-a-directory
  quit
  EOF
  ```

- **Contents:** `file.txt` (inode 12) with five attributes, `adir` (inode 13)
  with one.

  | node | attribute | bytes | stored in |
  |---|---|---|---|
  | `file.txt` | `user.small` | 10 | inode body |
  | `file.txt` | `user.comment` | 18 | inode body |
  | `file.txt` | `security.selinux` | 36 | **block 1293** |
  | `file.txt` | `trusted.marker` | 13 | **block 1293** |
  | `file.txt` | `user.big` | 2000 | **block 1293** |
  | `adir` | `user.ondir` | 14 | inode body |

- **Storage is decided by ORDER, not size.** ext4 fills the inode body and
  spills everything after it, so the 36-byte SELinux label is in the block while
  the 18-byte comment is not. Established by observation, not assumed:
  `debugfs -R "inode_dump -e file.txt"` shows only `small` and `comment` in the
  inode, and a raw scan of block 1293 finds `big`, `marker` and `selinux`.
  `debugfs -R "stat file.txt"` reports `File ACL: 1293`.
- **Namespace indices, read from the bytes e2fsprogs wrote** (a separate probe
  image, same recipe): `user`=1, `trusted`=4, `security`=**6**, `system`=**7**.
  This is what `ondisk::xattr::XattrNamespace` is checked against; the table had
  `6|7` both mapping to `System`, which reported `security.selinux` in the wrong
  namespace.
- **Ground truth:** `debugfs -R "ea_list file.txt"` lists every attribute with
  its length and value. The oracle is e2fsprogs, not this crate.
- **Redistribution:** none — self-minted from a Debian base image, no
  third-party data.
- **Committed gzipped** (16 MiB → 16 KiB); `flate2` is a dev-dependency and the
  test decompresses in-process.
- **MD5 (gz):** `6731ab58dcc33671897ac1a9e9edbf79`
- **MD5 (raw):** `de1492bd63c341f800c66b388b0b823e`
- **Used by:** `core/tests/vfs_xattr_streams.rs`
