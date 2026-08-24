//! Validate the ext4 analyzer against the repo's committed images.
//!
//! Tier-2 (real e2fsprogs output, ground truth recorded by the minting script —
//! see `tests/data/README.md`):
//!  - `minimal.img` is a clean 4 MiB ext4 with no deletions → the analyzer must
//!    find **zero** anomalies. A non-empty result is a false positive.
//!  - `forensic.img` deleted two files (`deleted-file.txt`, `deleted-large.txt`)
//!    before unmount → the recoverable-deleted-inode check must fire, and because
//!    deletion zeroed their link counts, the deleted-but-linked check must NOT —
//!    a true negative on an image that genuinely contains deletions.
//!
//! The deleted-but-linked contradiction has no fixture (no real image links a
//! stamped-deleted inode), so its positive control grades the predicate directly
//! (Tier-3, a detection heuristic — legitimate per the fleet evidence policy).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ext4fs::Ext4Fs;
use ext4fs_forensic::{analyze, is_deleted_but_linked, Ext4AnomalyKind};
use std::io::Cursor;

fn open(name: &str) -> Ext4Fs<Cursor<Vec<u8>>> {
    let path = format!("{}/../tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(&path).expect("read committed ext4 fixture");
    Ext4Fs::open(Cursor::new(data)).expect("open ext4 fixture")
}

#[test]
fn clean_image_has_no_findings() {
    let mut fs = open("minimal.img");
    let findings = analyze(&mut fs).expect("analyze minimal.img");
    assert!(
        findings.is_empty(),
        "expected no anomalies on a clean image, got {:?}",
        findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn forensic_image_surfaces_deleted_inodes() {
    let mut fs = open("forensic.img");
    let findings = analyze(&mut fs).expect("analyze forensic.img");

    // Ground truth (tests/data/README.md): two files were deleted before unmount.
    let deleted = findings
        .iter()
        .filter(|f| matches!(f.kind, Ext4AnomalyKind::DeletedInode { .. }))
        .count();
    assert!(
        deleted >= 2,
        "expected >= 2 deleted inodes on forensic.img, got {deleted}"
    );

    // True negative for the second check: real deletions zero the link count, so
    // none of them may be flagged deleted-but-linked.
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f.kind, Ext4AnomalyKind::DeletedButLinked { .. })),
        "a genuinely deleted inode must not trip the deleted-but-linked check"
    );
}

#[test]
fn deleted_but_linked_predicate_is_a_real_contradiction() {
    // Positive control: a deletion stamp on a still-linked inode fires.
    assert!(is_deleted_but_linked(1_700_000_000, 1));
    // A live inode (no deletion stamp) does not.
    assert!(!is_deleted_but_linked(0, 1));
    // A cleanly deleted inode (link count zeroed) does not.
    assert!(!is_deleted_but_linked(1_700_000_000, 0));
}
