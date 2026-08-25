//! ext4 filesystem forensic analyzer, and the reader it grades over.
//!
//! Emits [`forensicnomicon::report`] observations over an ext4 image parsed by
//! the [`ext4fs`] reader. Every finding is grounded in the filesystem's own
//! on-disk state — a deleted inode whose data blocks are still unallocated, an
//! inode carrying a deletion time while it is still linked — so it needs no
//! external oracle, and each is an *observation* ("consistent with"), never a
//! conclusion.
//!
//! The reader surface is re-exported, so `ext4fs_forensic::` resolves the reader
//! types too.
#![forbid(unsafe_code)]

pub use ext4fs::*;

use ext4fs::error::Ext4Error;
use forensicnomicon::report::{Category, Observation, Severity};
use std::io::{Read, Seek};

/// A graded anomaly observed in an ext4 filesystem.
#[derive(Debug, Clone, PartialEq)]
pub enum Ext4AnomalyKind {
    /// A deleted inode — the kernel set `dtime`. `fraction` is the share of the
    /// file's data blocks the reader found still unallocated (0.0–1.0): on ext4,
    /// deletion typically clears the extent tree, so content is often not
    /// directly recoverable (fraction 0.0) even though the deletion itself is
    /// evidenced by the surviving inode metadata. Consistent with a deleted file.
    DeletedInode { ino: u64, dtime: u32, fraction: f64 },
    /// An inode carries a non-zero deletion time (`dtime`) while its link count
    /// is still greater than zero. Deletion zeroes the link count, so a linked
    /// inode with a deletion stamp is a contradiction — consistent with an
    /// undelete that did not clear `dtime`, with tampering, or with corruption.
    DeletedButLinked {
        ino: u64,
        dtime: u32,
        links_count: u16,
    },
}

impl Ext4AnomalyKind {
    /// Severity — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            // A deleted inode is an evidentiary lead, not a tamper signal —
            // surfaced informationally.
            Ext4AnomalyKind::DeletedInode { .. } => Severity::Info,
            // A linked inode stamped as deleted violates an on-disk invariant.
            Ext4AnomalyKind::DeletedButLinked { .. } => Severity::Medium,
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            Ext4AnomalyKind::DeletedInode { .. } => Category::Residue,
            Ext4AnomalyKind::DeletedButLinked { .. } => Category::Integrity,
        }
    }

    /// Stable machine-readable code (published contract; never reused/renamed).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Ext4AnomalyKind::DeletedInode { .. } => "EXT4-INODE-DELETED",
            Ext4AnomalyKind::DeletedButLinked { .. } => "EXT4-DELETED-BUT-LINKED",
        }
    }

    /// Human-readable note (observation, not a conclusion). Offending values are
    /// shown verbatim.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            Ext4AnomalyKind::DeletedInode {
                ino,
                dtime,
                fraction,
            } => format!(
                "deleted inode {ino} (dtime={dtime}); {:.0}% of its data blocks are still \
                 unallocated — consistent with a deleted file (on ext4, deletion usually clears \
                 the extent tree, so 0% here still evidences the deletion via surviving metadata)",
                fraction * 100.0
            ),
            Ext4AnomalyKind::DeletedButLinked {
                ino,
                dtime,
                links_count,
            } => format!(
                "inode {ino} carries deletion time dtime={dtime} while links_count={links_count} \
                 (> 0) — a linked inode should have no deletion stamp; consistent with an undelete \
                 that did not clear dtime, tampering, or corruption"
            ),
        }
    }
}

/// A graded finding: an [`Ext4AnomalyKind`] plus its derived severity/code/note.
#[derive(Debug, Clone)]
pub struct Ext4Anomaly {
    pub kind: Ext4AnomalyKind,
    severity: Severity,
    code: &'static str,
    note: String,
}

impl Ext4Anomaly {
    #[must_use]
    pub fn new(kind: Ext4AnomalyKind) -> Self {
        let severity = kind.severity();
        let code = kind.code();
        let note = kind.note();
        Self {
            kind,
            severity,
            code,
            note,
        }
    }
}

impl Observation for Ext4Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
}

/// True when an inode's on-disk fields contradict each other: a deletion time is
/// stamped (`dtime != 0`) yet the inode is still linked (`links_count > 0`).
///
/// A pure predicate so the contradiction is testable without minting a tampered
/// image — the detection heuristic is graded directly.
#[must_use]
pub fn is_deleted_but_linked(dtime: u32, links_count: u16) -> bool {
    dtime != 0 && links_count > 0
}

/// Grade an opened ext4 filesystem, returning every anomaly it exhibits.
///
/// A clean image returns an empty vector: no recoverable deleted inodes and no
/// deletion-time contradictions.
pub fn analyze<R: Read + Seek>(fs: &mut Ext4Fs<R>) -> Result<Vec<Ext4Anomaly>, Ext4Error> {
    let mut out = Vec::new();

    // Every deleted inode is surfaced — the deletion is the evidence. The
    // reader's recoverability estimate (fraction of data blocks still
    // unallocated) is carried through so the note can say whether content
    // survives, without gating the finding on it.
    for d in fs.deleted_inodes()? {
        out.push(Ext4Anomaly::new(Ext4AnomalyKind::DeletedInode {
            ino: d.ino,
            dtime: d.dtime,
            fraction: d.recoverability,
        }));
    }

    // Deletion-time contradiction: dtime set on a still-linked inode.
    for (ino, inode) in fs.all_inodes()? {
        if is_deleted_but_linked(inode.dtime, inode.links_count) {
            out.push(Ext4Anomaly::new(Ext4AnomalyKind::DeletedButLinked {
                ino,
                dtime: inode.dtime,
                links_count: inode.links_count,
            }));
        }
    }

    Ok(out)
}
