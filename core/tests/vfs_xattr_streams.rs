//! Extended attributes must reach the VFS layer as STREAMS — under the name
//! the system actually gave them.
//!
//! This crate has read ext4 extended attributes for a long time
//! (`Ext4Fs::xattrs`), but nothing above `forensic-vfs` could see them: the
//! adapter refused every non-default `StreamId`. So a consumer walking an ext4
//! image saw files with no attributes, which on Linux silently drops
//! `SELinux` labels, capabilities and POSIX `ACLs`.
//!
//! ## The oracle is e2fsprogs, not this crate
//!
//! `tests/data/ext4_xattr.img.gz` was built and populated by `mkfs.ext4` and
//! `debugfs`, which then listed the attributes back:
//!
//! ```text
//! user.small (10) = "tiny-value"
//! user.comment (18) = "a second attribute"
//! user.big (2000)
//! trusted.marker (13) = "trusted-value"
//! security.selinux (36) = "unconfined_u:object_r:user_home_t:s0"
//! ```
//!
//! ## Two distinct things are pinned here
//!
//! **1. Storage form.** ext4 fills the inode body first and spills the rest into
//! a separate block pointed at by `i_file_acl` — `File ACL: 1293` here. It is
//! ORDER, not size: `security.selinux` is 36 bytes and still spilled, because
//! it was written after the ibody filled. Verified with `debugfs inode_dump -e`
//! (only `small` and `comment` in the inode) and a raw scan of block 1293
//! (`big`, `marker`, `selinux`). Where the bytes live is evidential, so it is
//! reported as residency rather than flattened.
//!
//! **2. Namespace.** ext4 does not store `"security.selinux"`; it stores name
//! `"selinux"` plus a one-byte `name_index`. The full name has to be
//! reconstructed, and getting the table wrong renames the artifact. The indices
//! were read out of bytes e2fsprogs wrote rather than recalled:
//!
//! | attribute written | observed `name_index` |
//! |---|---|
//! | `security.selinux` | **6** |
//! | `system.whatever` | **7** |
//! | `trusted.thing` | 4 |
//! | `user.plain` | 1 |

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::{FileId, FileSystem, ResidencyKind, StreamId, StreamKind};
use std::io::{Cursor, Read};

/// ext4 addresses nodes by inode number. `file.txt` is inode 12 and `adir` is
/// inode 13 per `debugfs stat`, recorded when the image was minted.
const FILE_INO: u64 = 12;
const DIR_INO: u64 = 13;

fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/ext4_xattr.img.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn fs() -> ext4fs::Ext4Fs<Cursor<Vec<u8>>> {
    ext4fs::Ext4Fs::open(Cursor::new(image())).expect("fixture must open as ext4")
}

fn id(ino: u64) -> FileId {
    FileId::ExtInode { ino, gen: 0 }
}

/// Collect `(name, size, residency)` for every attribute stream on `ino`.
fn xattrs_of(fs: &ext4fs::Ext4Fs<Cursor<Vec<u8>>>, ino: u64) -> Vec<(String, u64, ResidencyKind)> {
    fs.data_streams(id(ino))
        .expect("data_streams must not error")
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .map(|s| {
            (
                String::from_utf8_lossy(s.name.as_deref().unwrap_or(b"")).into_owned(),
                s.size,
                s.residency,
            )
        })
        .collect()
}

/// Every attribute e2fsprogs wrote must be listed, under its FULL name.
#[test]
fn data_streams_lists_every_extended_attribute() {
    let fs = fs();
    let x = xattrs_of(&fs, FILE_INO);

    // Non-zero baseline first: with an empty list every assertion below would
    // pass vacuously.
    assert_eq!(
        x.len(),
        5,
        "e2fsprogs listed 5 attributes on file.txt; got {x:?}"
    );

    let names: Vec<&str> = x.iter().map(|(n, _, _)| n.as_str()).collect();
    for want in [
        "user.small",
        "user.comment",
        "user.big",
        "trusted.marker",
        // The namespace prefix is reconstructed from name_index 6. Reporting
        // this as "system.selinux" would rename a SELinux label into a
        // namespace it does not belong to.
        "security.selinux",
    ] {
        assert!(names.contains(&want), "missing {want}; got {names:?}");
    }
}

/// Where the bytes live is a fact about the artifact, not an implementation
/// detail: a small value sits in the inode, a large one in its own block.
#[test]
fn residency_reports_where_the_value_actually_lives() {
    let fs = fs();
    let x = xattrs_of(&fs, FILE_INO);
    let find = |n: &str| -> (u64, ResidencyKind) {
        x.iter()
            .find(|(name, _, _)| name == n)
            .map_or_else(|| panic!("missing {n}; got {x:?}"), |(_, s, r)| (*s, *r))
    };

    assert_eq!(
        find("user.small"),
        (10, ResidencyKind::Resident { inline_len: 10 }),
        "a 10-byte value lives in the inode body"
    );
    // NOT a size threshold. This 36-byte label is SMALLER than the 2000-byte
    // value and still landed in the block, because the ibody had already filled
    // up. Confirmed independently before the expectation was changed:
    // `debugfs inode_dump -e file.txt` shows only `small` and `comment` in the
    // inode, and a raw scan of block 1293 finds `big`, `marker` and `selinux`.
    //
    // The first version of this test asserted Resident here on the assumption
    // that "small value => inline". The reader disagreed and the reader was
    // right; what ext4 does is fill the inode, then spill EVERYTHING after.
    assert_eq!(
        find("security.selinux").1,
        ResidencyKind::NonResident,
        "the ibody was already full, so this label went to block 1293 despite \
         being small -- residency reports where the bytes are, not how big they are"
    );
    assert_eq!(
        find("trusted.marker").1,
        ResidencyKind::NonResident,
        "likewise spilled: it was written after the inode body filled"
    );
    assert_eq!(
        find("user.comment"),
        (18, ResidencyKind::Resident { inline_len: 18 }),
        "written early, so it is still in the inode body"
    );
    assert_eq!(
        find("user.big"),
        (2000, ResidencyKind::NonResident),
        "debugfs reports File ACL: 1293 for this inode, so the 2000-byte value \
         spilled into its own block -- calling it Resident would say the bytes \
         are somewhere they are not"
    );
}

/// Listing is not reading. Values must come back byte-exact from both stores.
#[test]
fn read_at_returns_attribute_values_byte_exact() {
    let fs = fs();
    let streams = fs.data_streams(id(FILE_INO)).unwrap();
    let read = |name: &str| -> Vec<u8> {
        let s = streams
            .iter()
            .find(|s| s.kind == StreamKind::Xattr && s.name.as_deref() == Some(name.as_bytes()))
            .unwrap_or_else(|| panic!("no attribute {name}"));
        let mut buf = vec![0u8; usize::try_from(s.size).unwrap()];
        let n = fs
            .read_at(id(FILE_INO), s.id, 0, &mut buf)
            .unwrap_or_else(|e| panic!("read_at({name}) failed: {e:?}"));
        buf.truncate(n);
        buf
    };

    assert_eq!(read("user.small"), b"tiny-value");
    assert_eq!(read("user.comment"), b"a second attribute");
    assert_eq!(read("trusted.marker"), b"trusted-value");
    assert_eq!(
        read("security.selinux"),
        b"unconfined_u:object_r:user_home_t:s0"
    );
    // Byte-exact across all 2000: a block-stored value is read from a different
    // place entirely, so a wrong block or offset yields the right LENGTH and
    // the wrong bytes.
    assert_eq!(read("user.big"), vec![b'B'; 2000]);
}

/// Directories carry attributes too.
#[test]
fn directories_carry_attributes_as_well() {
    let fs = fs();
    let x = xattrs_of(&fs, DIR_INO);
    assert_eq!(x.len(), 1, "adir carries exactly one attribute: {x:?}");
    assert_eq!(x[0].0, "user.ondir");

    let streams = fs.data_streams(id(DIR_INO)).unwrap();
    let s = streams
        .iter()
        .find(|s| s.kind == StreamKind::Xattr)
        .expect("the attribute stream");
    let mut buf = vec![0u8; 64];
    let n = fs.read_at(id(DIR_INO), s.id, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"on-a-directory");
}

/// The file's own contents stay listed alongside its attributes.
#[test]
fn the_default_data_stream_is_still_reported() {
    let fs = fs();
    let streams = fs.data_streams(id(FILE_INO)).unwrap();
    assert!(
        streams.iter().any(|s| s.id == StreamId::Default),
        "the data stream must not be displaced by the attributes: {streams:?}"
    );
}

/// An attribute index past the list, and an offset past a value, are told
/// apart: the first is an error naming the index and the count, the second
/// reads zero bytes.
#[test]
fn read_at_refuses_an_unknown_index_and_reads_nothing_past_a_value() {
    let fs = fs();
    let streams = fs.data_streams(id(FILE_INO)).unwrap();
    let count = streams
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .count();
    let mut buf = [0u8; 16];
    let err = fs
        .read_at(id(FILE_INO), StreamId::Xattr(99), 0, &mut buf)
        .expect_err("there is no attribute 99");
    assert!(
        err.to_string()
            .contains(&format!("attribute 99 of {count}")),
        "{err}"
    );
    let small = streams
        .iter()
        .find(|s| s.name.as_deref() == Some(b"user.small".as_slice()))
        .expect("user.small");
    let past = small.size + 1;
    assert_eq!(
        fs.read_at(id(FILE_INO), small.id, past, &mut buf).unwrap(),
        0
    );
}

/// A namespace index the reader does not know is shown, not dropped or renamed:
/// `unknown.<index>.<name>`. The fixture's `user.small` entry (namespace 1) is
/// relabelled to index 9, which ext4 does not define.
#[test]
fn an_unknown_namespace_is_named_with_its_raw_index() {
    // ext4_xattr_entry: name_len(1) name_index(1) value_offs(2) value_inum(4)
    // value_size(4) hash(4), then the name. Find the one entry named "small".
    let mut img = image();
    let hits: Vec<usize> = img
        .windows(5)
        .enumerate()
        .filter(|(i, w)| *w == b"small" && *i >= 16 && img[i - 16] == 5 && img[i - 15] == 1)
        .map(|(i, _)| i - 15)
        .collect();
    assert_eq!(hits.len(), 1, "exactly one user.small entry: {hits:?}");
    img[hits[0]] = 9;
    let fs = ext4fs::Ext4Fs::open(Cursor::new(img)).expect("open");
    let names: Vec<String> = xattrs_of(&fs, FILE_INO)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    assert!(names.contains(&"unknown.9.small".to_string()), "{names:?}");
    assert!(!names.contains(&"user.small".to_string()), "{names:?}");
}
