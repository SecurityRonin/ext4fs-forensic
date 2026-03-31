#!/usr/bin/env bash
# tests/create-minimal-image.sh
# Creates minimal.img — a small ext4 image for unit testing.
# Requires: Linux, mkfs.ext4, mount (needs root), debugfs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="$SCRIPT_DIR/data/minimal.img"
MNT=$(mktemp -d)

mkdir -p "$SCRIPT_DIR/data"

# Create 4 MiB image with ext4, metadata_csum, extents, 64bit
dd if=/dev/zero of="$IMG" bs=1M count=4 2>/dev/null
mkfs.ext4 -F -b 4096 -O extents,metadata_csum,64bit,extra_isize -L "test-ext4" "$IMG" >/dev/null 2>&1

# Mount, write test files, unmount
sudo mount -o loop "$IMG" "$MNT"
echo -n "Hello, ext4!" | sudo tee "$MNT/hello.txt" >/dev/null
sudo mkdir "$MNT/subdir"
echo -n "Nested file" | sudo tee "$MNT/subdir/nested.txt" >/dev/null
sudo umount "$MNT"
rmdir "$MNT"

echo "Created $IMG"

# Print reference data for tests
echo "--- Reference data (use in tests) ---"
debugfs -R "stats" "$IMG" 2>/dev/null | head -20
echo "---"
debugfs -R "stat hello.txt" "$IMG" 2>/dev/null
echo "---"
debugfs -R "stat subdir/nested.txt" "$IMG" 2>/dev/null
