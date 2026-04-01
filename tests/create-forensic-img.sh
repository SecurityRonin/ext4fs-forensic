#!/bin/bash
# Create a forensic test image with journal, deleted files, symlinks, xattrs
# Requires Docker with a Linux container
set -euo pipefail

IMG="tests/data/forensic.img"
SIZE_MB=32

echo "Creating ${SIZE_MB}MB ext4 image with forensic artifacts..."

docker run --rm --privileged -v "$(pwd)/tests/data:/out" debian:bookworm-slim bash -c '
set -euo pipefail
apt-get update -qq && apt-get install -y -qq e2fsprogs attr >/dev/null 2>&1

IMG=/tmp/forensic.img
MNT=/mnt/ext4

# Create image with journal, metadata_csum, 64bit, extents
dd if=/dev/zero of=$IMG bs=1M count=32 2>/dev/null
mkfs.ext4 -F -L forensic-test -O has_journal,metadata_csum,64bit,extents -b 4096 $IMG >/dev/null 2>&1

mkdir -p $MNT
mount -o loop $IMG $MNT

# --- Regular files ---
echo "Hello, forensic world!" > $MNT/hello.txt
echo "Nested content" > $MNT/hello2.txt
mkdir -p $MNT/subdir
echo "File in subdirectory" > $MNT/subdir/nested.txt

# --- Symlinks ---
ln -s /hello.txt $MNT/abs-link          # absolute symlink
ln -s hello.txt $MNT/rel-link            # relative symlink
ln -s subdir/nested.txt $MNT/deep-link   # relative multi-component
mkdir -p $MNT/linkdir
ln -s ../hello.txt $MNT/linkdir/up-link  # relative with ..

# --- Extended attributes ---
setfattr -n user.forensic -v "evidence-tag" $MNT/hello.txt 2>/dev/null || true
setfattr -n user.case_id -v "2026-0401" $MNT/hello.txt 2>/dev/null || true

# --- File to be deleted (for deleted inode recovery) ---
echo "This file will be deleted - recover me!" > $MNT/deleted-file.txt
echo "Another deleted file with more content padding to fill a block" > $MNT/deleted-large.txt
# Pad it to be multi-block
dd if=/dev/urandom bs=4096 count=3 >> $MNT/deleted-large.txt 2>/dev/null

# --- Create a file with indirect blocks (disable extents for this file) ---
# We cannot easily disable extents per-file on a mounted fs, so skip this.
# Indirect block coverage will use synthetic tests.

# Sync to ensure journal has transactions
sync

# Record inode numbers before deletion
stat -c "%i" $MNT/deleted-file.txt > /out/deleted-ino.txt
stat -c "%i" $MNT/deleted-large.txt >> /out/deleted-ino.txt

# Delete files to create forensic artifacts
rm $MNT/deleted-file.txt
rm $MNT/deleted-large.txt

# Sync again
sync

umount $MNT

# Copy image out
cp $IMG /out/forensic.img
echo "Done: forensic.img created"
'

echo "Forensic image created at $IMG"
echo "Deleted inode numbers saved to tests/data/deleted-ino.txt"
