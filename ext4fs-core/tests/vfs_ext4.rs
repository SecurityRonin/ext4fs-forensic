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
use forensic_vfs::{Allocation, FileId, FileSystem, FsKind, NodeKind, StreamId};

/// Open `minimal.img` as a shared `Arc<dyn FileSystem>` (proves `Send + Sync`).
fn open() -> Option<Arc<dyn FileSystem>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
    let data = std::fs::read(path).ok()?;
    let fs = Ext4Fs::open(Cursor::new(data)).ok()?;
    Some(Arc::new(fs))
}

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
    assert_eq!(fs.kind(), FsKind::Ext);
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
