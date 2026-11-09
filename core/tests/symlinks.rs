//! Symlink targets read from real e2fsprogs images, at the fast/slow boundary.
//!
//! Fixtures `ext2_symlinks.img` and `ext4_symlinks.img` (256 KiB each, block
//! size 4096) were minted with `mke2fs -d` from one source directory holding
//! symlinks whose targets are 59, 60, 61 and 2000 bytes. Provenance and the
//! generator command are in `tests/data/README.md`. The oracle is the source
//! directory's `readlink`, which is independent of both e2fsprogs and this
//! crate; `debugfs` and `e2fsck -fn` (clean) confirm the images.
//!
//! The kernel stores a target in the inode (a "fast" symlink) only when it and
//! its NUL fit the 60-byte `i_block`, i.e. `i_size < 60` (fs/ext4/namei.c:
//! `disk_link.len > EXT4_N_BLOCKS * 4` selects a block; ext2 is the same). A
//! 60-byte target is therefore stored in a data block, and `debugfs` shows it
//! without "Fast link dest".

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use ext4fs::Ext4Fs;
use forensic_vfs::{FileId, FileSystem, NodeKind};

const ROOT: FileId = FileId::ExtInode { ino: 2, gen: 0 };

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

/// The target `ln -s` was given for `link<n>`: `t/` repeated, cut to `n` bytes.
fn expected(n: usize) -> Vec<u8> {
    b"t/".repeat(n).into_iter().take(n).collect()
}

fn read_all_links(image: Vec<u8>) {
    let fs = Ext4Fs::open(Cursor::new(image)).expect("open");
    for n in [59usize, 60, 61, 2000] {
        let name = format!("link{n}");
        let id = fs
            .lookup(ROOT, name.as_bytes())
            .unwrap()
            .unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(fs.meta(id).unwrap().kind, NodeKind::Symlink, "{name}");
        assert_eq!(fs.read_link(id, 4096).unwrap(), expected(n), "{name}");
    }
}

#[test]
fn ext2_symlink_targets_match_the_source_readlink() {
    read_all_links(fixture("ext2_symlinks.img"));
}

#[test]
fn ext4_symlink_targets_match_the_source_readlink() {
    read_all_links(fixture("ext4_symlinks.img"));
}

#[test]
fn a_symlink_of_a_whole_block_or_more_is_refused_loud() {
    // The kernel reads a slow symlink from block 0 only and never creates one
    // of block size or more (fscrypt_prepare_symlink with max_len =
    // s_blocksize, fs/ext4/namei.c). `link2000` is inode 12 at byte 142080
    // (`debugfs -R "imap /link2000"`: block 34, offset 0xb00); i_size_lo is at
    // +4. Declare it one block long.
    const I_SIZE_LO: usize = 142_080 + 4;
    let mut img = fixture("ext4_symlinks.img");
    assert_eq!(
        u32::from_le_bytes(img[I_SIZE_LO..I_SIZE_LO + 4].try_into().unwrap()),
        2000,
        "the fixture's link2000 i_size"
    );
    img[I_SIZE_LO..I_SIZE_LO + 4].copy_from_slice(&4096u32.to_le_bytes());
    let fs = Ext4Fs::open(Cursor::new(img)).expect("open");
    let id = fs.lookup(ROOT, b"link2000").unwrap().expect("present");
    let err = fs
        .read_link(id, 8192)
        .expect_err("a symlink of a whole block must be refused");
    let msg = err.to_string();
    assert!(msg.contains("4096") && msg.contains("block"), "{msg}");
}
