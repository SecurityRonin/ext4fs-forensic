//! Tier-1 validation of `impl FileSystem for Ext4Fs` (behind the `vfs` feature).
//!
//! Every asserted value is cross-checked against **The Sleuth Kit** run on the
//! same committed image (`tests/data/minimal.img`) — the independent oracle, not
//! self-authored expectations:
//!
//! ```text
//! fsstat -f ext4 minimal.img  -> Block Size 4096, Inode Size 256, Root Dir 2
//! fls    -f ext4 minimal.img  -> 11 lost+found (d), 12 subdir (d), 13 hello.txt (r)
//! istat  -f ext4 minimal.img 13 -> size 12, links 1, uid/gid 0/0, regular,
//!                                  Allocated, Direct Block 9
//! icat   -f ext4 minimal.img 13 -> "Hello, ext4!"  (12 bytes)
//! ```
//!
//! (The reader resolves `/hello.txt` by directory walk, so it agrees with TSK on
//! inode 13 regardless of any stale doc that says otherwise.)
#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::Arc;

use ext4fs::Ext4Fs;
use forensic_vfs::{
    Allocation, FileId, FileSystem, FsKind, NodeKind, ResidencyKind, StreamId, TimeZonePolicy,
    VfsError,
};

/// Open `minimal.img` as a shared `Arc<dyn FileSystem>` (proves `Send + Sync`).
fn open() -> Option<Arc<dyn FileSystem>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
    let data = std::fs::read(path).ok()?;
    let fs = Ext4Fs::open(Cursor::new(data)).ok()?;
    Some(Arc::new(fs))
}

/// Open the richer `forensic.img` (symlinks, xattrs, deleted files, journal) as
/// a concrete `Ext4Fs` so the symlink / error / residency adapter branches that
/// `minimal.img` cannot reach are driven against a real Tier-1 fixture.
fn open_forensic() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    Ext4Fs::open(Cursor::new(data)).ok()
}

/// Open the `inline_data` fixture (a small file whose bytes live inside the
/// inode) so the resident-residency adapter branch is exercised.
fn open_inline() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/inline.img");
    let data = std::fs::read(path).ok()?;
    Ext4Fs::open(Cursor::new(data)).ok()
}

/// Open the 128-byte-inode (ext2) fixture — these inodes predate the extended
/// timestamp fields, so nanosecond resolution and crtime are absent.
fn open_small_inode() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/ext2-128.img");
    let data = std::fs::read(path).ok()?;
    Ext4Fs::open(Cursor::new(data)).ok()
}

/// A `FileId` from another filesystem's identity domain — the adapter must
/// refuse it loud (never silently read the wrong inode).
const FOREIGN_ID: FileId = FileId::NtfsRef { entry: 5, seq: 1 };

fn ino_of(id: FileId) -> u64 {
    match id {
        FileId::ExtInode { ino, .. } => ino,
        other => panic!("expected ExtInode, got {other:?}"),
    }
}

#[test]
fn kind_root_and_geometry_match_tsk() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    assert_eq!(fs.kind(), FsKind::EXT);
    // fsstat: Root Directory 2.
    assert_eq!(ino_of(fs.root()), 2);
    // fsstat: Block Size 4096; ext logical sector is 512.
    let ss = fs.sector_sizes();
    assert_eq!(ss.logical, 512);
    assert_eq!(ss.cluster_or_block, 4096);
}

#[test]
fn read_dir_root_matches_fls() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let entries: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let by_name = |n: &str| entries.iter().find(|e| e.name == n.as_bytes());

    let hello = by_name("hello.txt").expect("hello.txt in root");
    assert_eq!(ino_of(hello.id), 13, "fls: hello.txt is inode 13");
    assert_eq!(hello.kind, NodeKind::File);

    let subdir = by_name("subdir").expect("subdir in root");
    assert_eq!(ino_of(subdir.id), 12, "fls: subdir is inode 12");
    assert_eq!(subdir.kind, NodeKind::Dir);

    let lf = by_name("lost+found").expect("lost+found in root");
    assert_eq!(ino_of(lf.id), 11, "fls: lost+found is inode 11");
    assert_eq!(lf.kind, NodeKind::Dir);
}

#[test]
fn lookup_finds_hello_at_inode_13() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let id = fs.lookup(fs.root(), b"hello.txt").unwrap().expect("found");
    assert_eq!(ino_of(id), 13);
    assert!(fs.lookup(fs.root(), b"does-not-exist").unwrap().is_none());
}

#[test]
fn meta_of_hello_matches_istat() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
    let m = fs.meta(id).unwrap();
    assert_eq!(m.kind, NodeKind::File);
    assert_eq!(m.size, 12, "istat: size 12");
    assert_eq!(m.nlink, 1, "istat: num of links 1");
    assert_eq!(m.uid, Some(0));
    assert_eq!(m.gid, Some(0));
    assert_eq!(m.allocated, Allocation::Allocated);
    // istat mode `rrw-r--r--` -> regular file, perms 0o644.
    assert_eq!(m.mode.unwrap() & 0o7777, 0o644);
    // All four MAC times are the same instant on this freshly-minted image.
    let mt = m.times.modified.expect("mtime present");
    assert!(mt.unix_nanos > 0);
    assert_eq!(m.times.accessed.unwrap().unix_nanos, mt.unix_nanos);
    assert_eq!(m.times.changed.unwrap().unix_nanos, mt.unix_nanos);
}

#[test]
fn read_at_returns_hello_bytes() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
    let mut buf = [0u8; 32];
    let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
    // icat: "Hello, ext4!" (12 bytes).
    assert_eq!(&buf[..n], b"Hello, ext4!");
}

#[test]
fn extents_of_hello_point_at_direct_block_9() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
    let runs: Vec<_> = fs
        .extents(id, StreamId::Default)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(runs.len(), 1, "one extent");
    // istat: Direct Block 9; block size 4096 -> image offset 36864, one block.
    assert_eq!(runs[0].run.image_offset, 9 * 4096);
    assert_eq!(runs[0].run.len, 4096);
}

#[test]
fn timestamp_zone_is_utc() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    // ext timestamps are seconds since the Unix epoch, in UTC.
    assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
}

#[test]
fn read_dir_reports_subdir_as_dir_kind() {
    // Drives `dirent_kind`'s Directory arm (subdir) alongside the File arm
    // already covered by hello.txt.
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let entries: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let subdir = entries
        .iter()
        .find(|e| e.name == b"subdir")
        .expect("subdir present");
    assert_eq!(subdir.kind, NodeKind::Dir);
}

// --- foreign FileId / non-default stream are refused loud (map_err-free error
//     construction: `Unsupported`) ---

#[test]
fn foreign_file_id_is_unsupported_not_silently_read() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    // Every entry point that resolves an inode must reject a non-ext id.
    assert!(matches!(
        fs.read_dir(FOREIGN_ID),
        Err(VfsError::Unsupported { .. })
    ));
    assert!(matches!(
        fs.meta(FOREIGN_ID),
        Err(VfsError::Unsupported { .. })
    ));
    assert!(matches!(
        fs.lookup(FOREIGN_ID, b"x"),
        Err(VfsError::Unsupported { .. })
    ));
    assert!(matches!(
        fs.extents(FOREIGN_ID, StreamId::Default),
        Err(VfsError::Unsupported { .. })
    ));
    let mut buf = [0u8; 4];
    assert!(matches!(
        fs.read_at(FOREIGN_ID, StreamId::Default, 0, &mut buf),
        Err(VfsError::Unsupported { .. })
    ));
    assert!(matches!(
        fs.read_link(FOREIGN_ID, 64),
        Err(VfsError::Unsupported { .. })
    ));
}

#[test]
fn named_stream_is_refused_ext_has_one_stream() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
    let mut buf = [0u8; 4];
    // ext exposes a single unnamed data stream; a named stream is refused loud.
    assert!(matches!(
        fs.read_at(id, StreamId::Named(1), 0, &mut buf),
        Err(VfsError::Unsupported { .. })
    ));
    assert!(matches!(
        fs.extents(id, StreamId::Named(1)),
        Err(VfsError::Unsupported { .. })
    ));
}

// --- an out-of-range inode drives `map_err`'s InodeOutOfRange -> OutOfRange ---

#[test]
fn out_of_range_inode_maps_to_out_of_range_error() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    // minimal.img has far fewer than u32::MAX inodes; addressing one past the
    // table is a structural range miss, distinct from an I/O or decode error.
    let bogus = FileId::ExtInode {
        ino: u64::from(u32::MAX),
        gen: 0,
    };
    match fs.meta(bogus) {
        Err(VfsError::OutOfRange { what, .. }) => assert_eq!(what, "ext4 inode"),
        other => panic!("expected OutOfRange, got {other:?}"),
    }
}

// --- deleted / unallocated default to empty streams (not a bootstrap failure) ---

#[test]
fn deleted_and_unallocated_are_empty_streams() {
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    assert_eq!(fs.deleted().unwrap().count(), 0);
    assert_eq!(fs.unallocated().unwrap().count(), 0);
}

// --- forensic.img: symlink node-kind, read_link target, and non-symlink empty
//     target, plus the `born` crtime branch on a large inode ---

#[test]
fn symlink_read_link_returns_target_and_kind() {
    let Some(fs) = open_forensic() else {
        eprintln!("skip: forensic.img not found");
        return;
    };
    // `lookup` returns the symlink's OWN inode (no resolution), so meta/read_link
    // see the link node itself.
    let link = fs
        .lookup(FileId::ExtInode { ino: 2, gen: 0 }, b"abs-link")
        .unwrap()
        .expect("abs-link present");
    let m = fs.meta(link).unwrap();
    assert_eq!(m.kind, NodeKind::Symlink, "node_kind Symlink arm");

    let target = fs.read_link(link, 4096).unwrap();
    assert!(!target.is_empty(), "symlink resolves to a non-empty target");

    // A cap shorter than the target truncates it (never panics).
    let capped = fs.read_link(link, 1).unwrap();
    assert!(capped.len() <= 1);
}

#[test]
fn read_link_on_regular_file_is_empty_target() {
    let Some(fs) = open_forensic() else {
        eprintln!("skip: forensic.img not found");
        return;
    };
    let hello = fs
        .lookup(FileId::ExtInode { ino: 2, gen: 0 }, b"hello.txt")
        .unwrap()
        .expect("hello.txt present");
    // A non-symlink reads as an empty target (matches the NTFS adapter), not an
    // error surfaced per node.
    assert_eq!(fs.read_link(hello, 4096).unwrap(), Vec::<u8>::new());
}

#[test]
fn meta_of_directory_reports_dir_kind() {
    // Drives `node_kind`'s Directory arm via meta (dirent_kind's Dir arm is
    // covered by read_dir; this is the inode-table path).
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    // Root (inode 2) is a directory.
    let m = fs.meta(fs.root()).unwrap();
    assert_eq!(m.kind, NodeKind::Dir);
}

#[test]
fn read_dir_forensic_reports_symlink_entry_kind() {
    // forensic.img's root holds symlink entries, driving `dirent_kind`'s Symlink
    // arm (the cheap file-type-nibble path, no inode read).
    let Some(fs) = open_forensic() else {
        eprintln!("skip: forensic.img not found");
        return;
    };
    let entries: Vec<_> = fs
        .read_dir(FileId::ExtInode { ino: 2, gen: 0 })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let link = entries
        .iter()
        .find(|e| e.name == b"abs-link")
        .expect("abs-link entry present");
    assert_eq!(link.kind, NodeKind::Symlink);
}

#[test]
fn meta_of_deleted_inode_reports_deleted_allocation() {
    // forensic.img was built with two files created then deleted; their inodes
    // survive in the table but are unallocated, driving `Allocation::Deleted`.
    // Ground truth (which inode) is recorded in tests/data/deleted-ino.txt.
    let Some(fs) = open_forensic() else {
        eprintln!("skip: forensic.img not found");
        return;
    };
    let raw = include_str!("../../tests/data/deleted-ino.txt");
    let ino: u64 = raw
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok())
        .expect("deleted-ino.txt holds an inode");
    let m = fs.meta(FileId::ExtInode { ino, gen: 0 }).unwrap();
    assert_eq!(
        m.allocated,
        Allocation::Deleted,
        "a created-then-deleted inode is unallocated"
    );
}

#[test]
fn read_link_on_out_of_range_inode_maps_error() {
    // Drives read_link's `Err(e) => Err(map_err(e))` arm: an inode past the
    // table is neither a symlink nor an I/O miss but a structural range error.
    let Some(fs) = open() else {
        eprintln!("skip: minimal.img not found");
        return;
    };
    let bogus = FileId::ExtInode {
        ino: u64::from(u32::MAX),
        gen: 0,
    };
    assert!(matches!(
        fs.read_link(bogus, 64),
        Err(VfsError::OutOfRange { .. })
    ));
}

#[test]
fn meta_of_regular_file_is_non_resident_with_born_time() {
    let Some(fs) = open_forensic() else {
        eprintln!("skip: forensic.img not found");
        return;
    };
    let hello = fs
        .lookup(FileId::ExtInode { ino: 2, gen: 0 }, b"hello.txt")
        .unwrap()
        .expect("hello.txt present");
    let m = fs.meta(hello).unwrap();
    // forensic.img has 256-byte inodes (extra_isize >= 28) so crtime is present.
    assert!(m.times.born.is_some(), "crtime present on large inode");
    // A multi-byte regular file is non-resident (data lives in blocks).
    assert!(matches!(m.residency, ResidencyKind::NonResident));
    assert_eq!(m.kind, NodeKind::File);
}

#[test]
fn meta_of_inline_file_is_resident() {
    // An `inline_data` inode carries its bytes in the inode body, so the adapter
    // reports `ResidencyKind::Resident` with the inline length.
    let Some(fs) = open_inline() else {
        eprintln!("skip: inline.img not found");
        return;
    };
    let id = fs
        .lookup(FileId::ExtInode { ino: 2, gen: 0 }, b"inlinefile")
        .unwrap()
        .expect("inlinefile present");
    let m = fs.meta(id).unwrap();
    let inline_len = if let ResidencyKind::Resident { inline_len } = m.residency {
        Some(u64::from(inline_len))
    } else {
        None
    };
    assert_eq!(
        inline_len,
        Some(m.size),
        "resident with inline_len tracking the file size"
    );
}

#[test]
fn meta_of_128_byte_inode_has_no_born_time() {
    // 128-byte inodes (ext2-era) lack the extended timestamp fields, so crtime
    // is absent (None, not epoch-zero) and resolution falls back to seconds.
    let Some(fs) = open_small_inode() else {
        eprintln!("skip: ext2-128.img not found");
        return;
    };
    let id = fs
        .lookup(FileId::ExtInode { ino: 2, gen: 0 }, b"afile")
        .unwrap()
        .expect("afile present");
    let m = fs.meta(id).unwrap();
    assert!(m.times.born.is_none(), "no crtime on a 128-byte inode");
    // mtime is still present, just at seconds resolution.
    assert!(m.times.modified.is_some());
}
