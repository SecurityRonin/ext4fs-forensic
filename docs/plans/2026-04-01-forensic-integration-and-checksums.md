# Forensic Integration Tests & Checksum Verification

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add forensic integration tests against `forensic.img` (deleted detection, timeline with deletion events, xattr reading, extent carving) and implement CRC32C checksum verification for group descriptors and inodes.

**Architecture:** The `forensic.img` test image (32MB, created by `tests/create-forensic-img.sh`) contains known deleted files (inodes 21, 22), xattrs on `/hello.txt`, symlinks, and a journal. Tests will open it like `minimal.img` via `Cursor<Vec<u8>>`. Checksum verification follows the existing superblock pattern: compute CRC32C over the structure bytes (seeded with UUID-derived seed), compare against stored checksum, return `bool`.

**Tech Stack:** Rust, `crc` 3.x (CRC32C via `EXT4_CRC32C` algorithm), `bitflags` 2.x

---

### Task 1: Forensic Integration — Deleted Inode Detection on forensic.img

**Files:**
- Modify: `ext4fs/src/forensic/deleted.rs:149-202` (test module)

**Step 1: Write the failing tests**

Add to the existing `tests` module in `deleted.rs`:

```rust
fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
    Some(InodeReader::new(block_reader))
}

#[test]
fn forensic_image_has_deleted_inodes() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let deleted = find_deleted_inodes(&mut reader).unwrap();
    // forensic.img has 2 deleted files: inodes 21 and 22
    assert!(deleted.len() >= 2, "expected >= 2 deleted inodes, got {}", deleted.len());

    let inos: Vec<u64> = deleted.iter().map(|d| d.ino).collect();
    assert!(inos.contains(&21), "expected deleted inode 21, found: {:?}", inos);
    assert!(inos.contains(&22), "expected deleted inode 22, found: {:?}", inos);
}

#[test]
fn deleted_inode_has_nonzero_dtime() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let deleted = find_deleted_inodes(&mut reader).unwrap();
    for d in &deleted {
        assert!(d.dtime > 0, "deleted inode {} should have dtime > 0", d.ino);
    }
}

#[test]
fn deleted_inode_recoverability_is_valid() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let deleted = find_deleted_inodes(&mut reader).unwrap();
    for d in &deleted {
        assert!(
            (0.0..=1.0).contains(&d.recoverability),
            "recoverability for inode {} should be in [0.0, 1.0], got {}",
            d.ino, d.recoverability
        );
    }
}

#[test]
fn deleted_inode_21_is_regular_file() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let deleted = find_deleted_inodes(&mut reader).unwrap();
    let ino21 = deleted.iter().find(|d| d.ino == 21).expect("inode 21 not found");
    assert_eq!(ino21.file_type, FileType::RegularFile);
}
```

**Step 2: Run tests to verify they pass (these are integration tests against existing implementation)**

Run: `cargo test -p ext4fs deleted -- --nocapture`
Expected: All 4 new tests PASS (the implementation already exists, we are adding coverage)

**Step 3: Commit**

```
test: forensic.img integration tests for deleted inode detection
```

---

### Task 2: Forensic Integration — Timeline with Deletion Events

**Files:**
- Modify: `ext4fs/src/forensic/timeline.rs:86-112` (test module)

**Step 1: Write the failing tests**

Add to existing `tests` module in `timeline.rs`:

```rust
fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    let br = BlockReader::open(Cursor::new(data)).ok()?;
    Some(InodeReader::new(br))
}

#[test]
fn forensic_timeline_contains_deletion_events() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let events = generate_timeline(&mut reader).unwrap();
    let deletions: Vec<_> = events.iter()
        .filter(|e| e.event_type == EventType::Deleted)
        .collect();
    assert!(!deletions.is_empty(), "forensic.img should have deletion events");
    // Deleted inodes 21 and 22
    let del_inos: Vec<u64> = deletions.iter().map(|e| e.inode).collect();
    assert!(del_inos.contains(&21), "deletion event for inode 21 missing");
    assert!(del_inos.contains(&22), "deletion event for inode 22 missing");
}

#[test]
fn forensic_timeline_contains_all_event_types() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let events = generate_timeline(&mut reader).unwrap();
    let has_created = events.iter().any(|e| e.event_type == EventType::Created);
    let has_modified = events.iter().any(|e| e.event_type == EventType::Modified);
    let has_accessed = events.iter().any(|e| e.event_type == EventType::Accessed);
    let has_changed = events.iter().any(|e| e.event_type == EventType::Changed);
    let has_deleted = events.iter().any(|e| e.event_type == EventType::Deleted);
    assert!(has_created, "missing Created events");
    assert!(has_modified, "missing Modified events");
    assert!(has_accessed, "missing Accessed events");
    assert!(has_changed, "missing Changed events");
    assert!(has_deleted, "missing Deleted events");
}

#[test]
fn forensic_timeline_is_sorted() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let events = generate_timeline(&mut reader).unwrap();
    for window in events.windows(2) {
        assert!(
            window[0].timestamp <= window[1].timestamp,
            "timeline not sorted: {:?} > {:?}",
            window[0].timestamp, window[1].timestamp
        );
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p ext4fs timeline -- --nocapture`
Expected: All 3 new tests PASS

**Step 3: Commit**

```
test: forensic.img timeline integration tests with deletion events
```

---

### Task 3: Forensic Integration — Xattr Reading on forensic.img

**Files:**
- Modify: `ext4fs/src/forensic/xattr.rs:59-82` (test module)

The forensic.img has `user.forensic=evidence-tag` and `user.case_id=2026-0401` on `/hello.txt`. However, these may be stored as inline xattrs (in the inode body) rather than block xattrs — small xattrs usually go inline. We need to test what the current implementation returns and, if empty, note that inline xattr support is needed.

**Step 1: Write the tests**

Add to existing `tests` module in `xattr.rs`:

```rust
fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    let br = BlockReader::open(Cursor::new(data)).ok()?;
    Some(InodeReader::new(br))
}

#[test]
fn read_xattrs_for_hello_txt() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    // hello.txt is inode 12 in forensic.img (first file after reserved + dirs)
    // We need to find it — iterate to locate it by checking dir entries
    // For now, read inode 12 xattrs (typical first user file inode)
    let xattrs = read_xattrs(&mut reader, 12).unwrap();
    // forensic.img has user.forensic and user.case_id set on hello.txt
    // These may be inline (ibody) xattrs — if so, this returns empty and
    // we need Task 6 (inline xattr support) to read them
    let _ = xattrs; // assertion deferred — see Step 2
}

#[test]
fn read_xattrs_for_root_inode() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    // Root inode (2) — typically no user xattrs, should not error
    let xattrs = read_xattrs(&mut reader, 2).unwrap();
    let _ = xattrs;
}
```

**Step 2: Run tests and observe — determine if xattrs are block-stored or inline**

Run: `cargo test -p ext4fs forensic::xattr -- --nocapture`

If hello.txt xattrs come back empty, the xattrs are inline (ibody) and Task 6 is needed.
If they come back with entries, add assertions for `user.forensic` and `user.case_id`.

**Step 3: Commit**

```
test: forensic.img xattr integration tests
```

---

### Task 4: Forensic Integration — Extent Signature Carving

**Files:**
- Modify: `ext4fs/src/forensic/carving.rs:109-135` (test module)

**Step 1: Write the tests**

Add to existing `tests` module in `carving.rs`:

```rust
fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    let br = BlockReader::open(Cursor::new(data)).ok()?;
    Some(InodeReader::new(br))
}

#[test]
fn find_extent_signatures_runs_without_error() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let ranges = unallocated_blocks(&mut reader).unwrap();
    let carved = find_extent_signatures(&mut reader, &ranges).unwrap();
    // We don't assert specific count — just that it runs and returns valid data
    for c in &carved {
        assert!(c.offset_in_block % 12 == 0, "offset should be 12-byte aligned");
    }
}

#[test]
fn read_unallocated_returns_data() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let ranges = unallocated_blocks(&mut reader).unwrap();
    assert!(!ranges.is_empty());
    let first = &ranges[0];
    let data = read_unallocated(&mut reader, first).unwrap();
    let block_size = reader.block_reader().superblock().block_size() as usize;
    assert_eq!(data.len(), first.length as usize * block_size);
}

#[test]
fn forensic_image_has_unallocated_blocks() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let ranges = unallocated_blocks(&mut reader).unwrap();
    assert!(!ranges.is_empty(), "32MB image should have unallocated blocks");
    let total: u64 = ranges.iter().map(|r| r.length).sum();
    // 32MB with only a few small files — most blocks should be free
    assert!(total > 100, "expected many free blocks, got {}", total);
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p ext4fs carving -- --nocapture`
Expected: All 3 new tests PASS

**Step 3: Commit**

```
test: forensic.img carving integration tests including find_extent_signatures
```

---

### Task 5: CRC32C Group Descriptor Checksum Verification

**Files:**
- Modify: `ext4fs/src/ondisk/group_desc.rs` (add `verify_checksum` method)
- Modify: `ext4fs/src/ondisk/superblock.rs` (import `EXT4_CRC32C` — already `pub(crate)`)

Group descriptor checksums in ext4 with `METADATA_CSUM`:
- Seed = CRC32C(UUID) — or `checksum_seed` if `CSUM_SEED` feature flag is set
- CRC = CRC32C(seed, group_number_le32)
- CRC = CRC32C(CRC, descriptor_bytes_excluding_checksum_field)
- Stored checksum is truncated to 16 bits (lower 16 of CRC32C result)
- The checksum field is at offset 0x1E (2 bytes); bytes before and after it are checksummed

**Step 1: Write the failing test**

Add to `group_desc.rs` test module:

```rust
#[test]
fn verify_group_descriptor_checksum_on_forensic_img() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skip: forensic.img not found"); return; }
    };
    use crate::ondisk::superblock::Superblock;
    let sb = Superblock::parse(&data[1024..]).unwrap();
    assert!(sb.has_metadata_csum(), "forensic.img should have metadata_csum");

    let desc_size = sb.desc_size;
    let gdt_offset = if sb.block_size() >= 2048 {
        sb.block_size() as usize
    } else {
        2048
    };

    // Verify first group descriptor
    let gd_buf = &data[gdt_offset..gdt_offset + desc_size as usize];
    let gd = GroupDescriptor::parse(gd_buf, desc_size).unwrap();
    assert!(
        gd.verify_checksum(gd_buf, &sb.uuid, 0, sb.checksum_seed),
        "group 0 descriptor checksum should verify"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ext4fs verify_group_descriptor_checksum -- --nocapture`
Expected: FAIL — `verify_checksum` method does not exist

**Step 3: Write minimal implementation**

Add to `GroupDescriptor` impl in `group_desc.rs`:

```rust
use crate::ondisk::superblock::EXT4_CRC32C;
use crc::Crc;

/// Verify the group descriptor CRC32C checksum.
///
/// For `METADATA_CSUM` filesystems, the checksum is:
///   crc32c(seed, le32(group_number)) over all descriptor bytes
///   except the 2-byte checksum field at offset 0x1E.
///   The stored checksum is the low 16 bits of the full CRC32C.
///
/// `uuid` is the filesystem UUID from the superblock.
/// `group` is the zero-based group number.
/// `csum_seed` is `sb.checksum_seed` (nonzero when CSUM_SEED feature is set).
pub fn verify_checksum(
    &self,
    raw_buf: &[u8],
    uuid: &[u8; 16],
    group: u32,
    csum_seed: u32,
) -> bool {
    let crc32c = Crc::<u32>::new(&EXT4_CRC32C);

    // Seed: either stored checksum_seed or CRC32C(UUID)
    let seed = if csum_seed != 0 {
        csum_seed
    } else {
        let mut d = crc32c.digest();
        d.update(uuid);
        d.finalize()
    };

    let mut digest = crc32c.digest_with_initial(seed);
    digest.update(&group.to_le_bytes());

    // Hash everything except the 2-byte checksum at offset 0x1E
    if raw_buf.len() > 0x1E {
        digest.update(&raw_buf[..0x1E]);
        if raw_buf.len() > 0x20 {
            digest.update(&raw_buf[0x20..]);
        }
    } else {
        digest.update(raw_buf);
    }

    let computed = digest.finalize() & 0xFFFF;
    computed as u16 == self.checksum
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ext4fs verify_group_descriptor_checksum -- --nocapture`
Expected: PASS

**Step 5: Commit**

```
feat: CRC32C checksum verification for group descriptors
```

---

### Task 6: CRC32C Inode Checksum Verification

**Files:**
- Modify: `ext4fs/src/ondisk/inode.rs` (add `verify_checksum` method)

Inode checksums in ext4 with `METADATA_CSUM`:
- Seed = CRC32C(UUID) — or `checksum_seed`
- CRC = CRC32C(seed, inode_number_le32)
- CRC = CRC32C(CRC, inode_generation_le32)
- CRC = CRC32C(CRC, inode_bytes_with_checksum_fields_zeroed)
- The 32-bit checksum is split: low 16 bits at offset 0x7C, high 16 bits at 0x82
- Both checksum fields must be zeroed before computing

**Step 1: Write the failing test**

Add to `inode.rs` test module:

```rust
#[test]
fn verify_inode_checksum_on_forensic_img() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skip: forensic.img not found"); return; }
    };
    use crate::ondisk::superblock::Superblock;
    use crate::block::BlockReader;
    use std::io::Cursor;

    let sb = Superblock::parse(&data[1024..]).unwrap();
    assert!(sb.has_metadata_csum(), "forensic.img should have metadata_csum");

    let mut block_reader = BlockReader::open(Cursor::new(data)).unwrap();
    let inode_reader = crate::inode::InodeReader::new(block_reader);

    // Read raw inode bytes for inode 2 (root) and verify checksum
    // We need raw bytes, so we'll read from the inode table directly
    let sb_ref = inode_reader.block_reader().superblock();
    let inode_size = sb_ref.inode_size;
    let inodes_per_group = sb_ref.inodes_per_group;
    let uuid = sb_ref.uuid;
    let csum_seed = sb_ref.checksum_seed;

    // Inode 12 (hello.txt) — guaranteed to be a regular allocated inode
    let ino: u64 = 12;
    let group = ((ino - 1) / inodes_per_group as u64) as u32;
    let index = ((ino - 1) % inodes_per_group as u64) as u64;
    let inode_table_block = inode_reader.block_reader().group_descriptors()[group as usize].inode_table;

    let block_size = sb_ref.block_size() as u64;
    let byte_offset = inode_table_block * block_size + index * inode_size as u64;

    // Read raw inode from image data directly
    let raw = &data[byte_offset as usize..(byte_offset + inode_size as u64) as usize];
    let inode = Inode::parse(raw, inode_size).unwrap();

    assert!(
        inode.verify_checksum(raw, &uuid, ino as u32, inode.generation, csum_seed),
        "inode 12 checksum should verify"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ext4fs verify_inode_checksum -- --nocapture`
Expected: FAIL — `verify_checksum` method does not exist

**Step 3: Write minimal implementation**

Add to `Inode` impl in `inode.rs`:

```rust
use crate::ondisk::superblock::EXT4_CRC32C;
use crc::Crc;

/// Verify the inode CRC32C checksum.
///
/// For `METADATA_CSUM` filesystems:
///   seed = crc32c(uuid) (or checksum_seed if nonzero)
///   crc = crc32c(seed, le32(ino))
///   crc = crc32c(crc, le32(generation))
///   crc = crc32c(crc, inode_bytes_with_checksum_zeroed)
///   Stored checksum: lo16 at 0x7C, hi16 at 0x82
pub fn verify_checksum(
    &self,
    raw_buf: &[u8],
    uuid: &[u8; 16],
    ino: u32,
    generation: u32,
    csum_seed: u32,
) -> bool {
    let crc32c = Crc::<u32>::new(&EXT4_CRC32C);

    let seed = if csum_seed != 0 {
        csum_seed
    } else {
        let mut d = crc32c.digest();
        d.update(uuid);
        d.finalize()
    };

    let mut digest = crc32c.digest_with_initial(seed);
    digest.update(&ino.to_le_bytes());
    digest.update(&generation.to_le_bytes());

    // Zero out the checksum fields before computing
    let mut buf = raw_buf.to_vec();
    // lo16 at 0x7C
    if buf.len() > 0x7E {
        buf[0x7C] = 0;
        buf[0x7D] = 0;
    }
    // hi16 at 0x82 (only if extended inode)
    if buf.len() > 0x84 {
        buf[0x82] = 0;
        buf[0x83] = 0;
    }
    digest.update(&buf);

    let computed = digest.finalize();
    computed == self.checksum
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ext4fs verify_inode_checksum -- --nocapture`
Expected: PASS

**Step 5: Commit**

```
feat: CRC32C checksum verification for inodes
```

---

### Task 7: Inline Xattr Support

**Files:**
- Modify: `ext4fs/src/forensic/xattr.rs` (add inline xattr reading)
- Modify: `ext4fs/src/ondisk/inode.rs` (expose ibody xattr region)

Inline xattrs are stored in the inode body after the fixed fields. The region starts at offset `0x80 + extra_isize` and extends to `inode_size`. The layout is identical to block xattrs (entries followed by values) but without the 32-byte `XattrBlockHeader` — instead there's a 4-byte magic `0xEA020000` that may or may not be present. Actually, inline xattrs have NO header — entries start immediately at the ibody offset.

**Step 1: Write the failing test**

Add to `forensic/xattr.rs` tests:

```rust
#[test]
fn read_inline_xattrs_for_hello_txt() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    // hello.txt should have user.forensic and user.case_id xattrs
    // We need to find the inode for hello.txt first
    // In forensic.img, hello.txt is typically inode 12
    let xattrs = read_xattrs(&mut reader, 12).unwrap();
    let names: Vec<String> = xattrs.iter()
        .map(|x| String::from_utf8_lossy(&x.name).to_string())
        .collect();
    assert!(
        names.contains(&"forensic".to_string()),
        "expected user.forensic xattr, found: {:?}", names
    );
    assert!(
        names.contains(&"case_id".to_string()),
        "expected user.case_id xattr, found: {:?}", names
    );
}

#[test]
fn inline_xattr_values_are_correct() {
    let mut reader = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let xattrs = read_xattrs(&mut reader, 12).unwrap();
    let forensic_xattr = xattrs.iter()
        .find(|x| x.name == b"forensic")
        .expect("user.forensic xattr not found");
    assert_eq!(
        String::from_utf8_lossy(&forensic_xattr.value),
        "evidence-tag"
    );

    let case_xattr = xattrs.iter()
        .find(|x| x.name == b"case_id")
        .expect("user.case_id xattr not found");
    assert_eq!(
        String::from_utf8_lossy(&case_xattr.value),
        "2026-0401"
    );
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ext4fs inline_xattr -- --nocapture`
Expected: FAIL — the xattrs are inline and `read_xattrs` only reads block xattrs

**Step 3: Implement inline xattr reading**

First, expose the raw inode bytes from `InodeReader`. Add to `ext4fs/src/inode.rs`:

```rust
/// Read the raw inode bytes for an inode number.
/// Returns the full inode-sized buffer from the inode table.
pub fn read_inode_raw(&mut self, ino: u64) -> Result<Vec<u8>> {
    let sb = self.block_reader.superblock();
    let inode_size = sb.inode_size as u64;
    let inodes_per_group = sb.inodes_per_group as u64;
    if ino < 1 || ino > sb.inodes_count {
        return Err(crate::error::Ext4Error::InodeOutOfRange {
            ino,
            max: sb.inodes_count,
        });
    }
    let group = ((ino - 1) / inodes_per_group) as u32;
    let index = (ino - 1) % inodes_per_group;
    let inode_table_block = self.block_reader.group_descriptors()[group as usize].inode_table;
    let block_size = sb.block_size() as u64;
    let byte_offset = inode_table_block * block_size + index * inode_size;
    self.block_reader.read_bytes(byte_offset, inode_size as usize)
}
```

Then update `read_xattrs` in `forensic/xattr.rs` to also read inline xattrs:

```rust
pub fn read_xattrs<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<Vec<Xattr>> {
    let inode = reader.read_inode(ino)?;
    let mut xattrs = Vec::new();

    // --- Inline xattrs (ibody) ---
    // Inline xattrs live in the inode body at offset (0x80 + extra_isize)
    // up to inode_size. They use the same entry format as block xattrs
    // but without the 32-byte XattrBlockHeader.
    let inode_size = reader.block_reader().superblock().inode_size as usize;
    if inode.extra_isize > 0 && inode_size > 0x80 + inode.extra_isize as usize {
        let raw = reader.read_inode_raw(ino)?;
        let ibody_offset = 0x80 + inode.extra_isize as usize;
        let ibody_region = &raw[ibody_offset..];
        // Inline xattr entries start at ibody_offset + 4 (skip 4-byte magic 0xEA020000)
        // But some kernels don't write the magic for ibody xattrs — entries start directly.
        // We'll check for the magic and skip it if present.
        let entry_start = if ibody_region.len() >= 4 {
            let magic = u32::from_le_bytes([
                ibody_region[0], ibody_region[1],
                ibody_region[2], ibody_region[3],
            ]);
            if magic == 0x0000_02EA { 4 } else { 0 }
        } else {
            0
        };
        let entry_region = &ibody_region[entry_start..];
        let mut offset = 0;
        while offset + 16 <= entry_region.len() {
            if entry_region[offset] == 0 { break; }
            match XattrEntry::parse(&entry_region[offset..]) {
                Ok(entry) => {
                    // For inline xattrs, value_offset is relative to the
                    // start of the first entry (after the optional magic)
                    let value_start = entry.value_offset as usize;
                    let value_end = value_start + entry.value_size as usize;
                    let value = if value_end <= ibody_region.len() {
                        ibody_region[value_start..value_end].to_vec()
                    } else {
                        Vec::new()
                    };
                    xattrs.push(Xattr {
                        namespace: entry.name_index,
                        name: entry.name.clone(),
                        value,
                    });
                    offset += entry.entry_size;
                }
                Err(_) => break,
            }
        }
    }

    // --- Block xattrs (from i_file_acl) ---
    if inode.file_acl != 0 {
        let block_data = reader.block_reader_mut().read_block(inode.file_acl)?;
        if let Ok(_header) = XattrBlockHeader::parse(&block_data) {
            let mut offset = 32;
            while offset + 16 <= block_data.len() {
                if block_data[offset] == 0 { break; }
                match XattrEntry::parse(&block_data[offset..]) {
                    Ok(entry) => {
                        let value_start = entry.value_offset as usize;
                        let value_end = value_start + entry.value_size as usize;
                        let value = if value_end <= block_data.len() {
                            block_data[value_start..value_end].to_vec()
                        } else {
                            Vec::new()
                        };
                        xattrs.push(Xattr {
                            namespace: entry.name_index,
                            name: entry.name.clone(),
                            value,
                        });
                        offset += entry.entry_size;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(xattrs)
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ext4fs xattr -- --nocapture`
Expected: PASS

Note: if tests still fail, the xattr value_offset for inline xattrs may need adjustment. The kernel stores inline xattr values growing downward from the end of the ibody region, with offsets relative to the start of the ibody region (after the fixed inode header). Debug by printing raw bytes and adjusting offset calculations.

**Step 5: Commit**

```
feat: inline xattr (ibody) support for forensic xattr reading
```

---
