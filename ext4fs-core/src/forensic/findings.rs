//! ext4 forensic findings: a thin [`forensicnomicon::report::Observation`]
//! adapter over the existing `forensic` engine.
//!
//! This module performs **no new parsing**. It *surfaces* what the engine has
//! already computed — superblock-backup comparisons, deleted inodes, file slack,
//! and journal transactions — as graded `EXT4-*` [`Finding`](forensicnomicon::report::Finding)s, so a
//! disk-forensic / Issen orchestrator can aggregate ext4 findings uniformly
//! alongside the partition and other filesystem layers.
//!
//! Every variant's severity, stable machine-readable code, and human-readable
//! note are *derived* from its classification, so they cannot drift. Findings
//! are observations in "consistent with" language, never verdicts: a
//! superblock-backup divergence, for instance, has benign causes (a resize that
//! never propagated, a `tune2fs` edit) and is graded as a consistency anomaly,
//! not "tamper detected".

use crate::forensic::deleted::DeletedInode;
use crate::forensic::journal::Journal;
use crate::forensic::slack::SlackSpace;
use crate::forensic::superblock_verify::SuperblockComparison;
use crate::ondisk::FileType;

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Category, Observation};

/// A classified ext4 forensic anomaly, carrying the engine evidence needed to
/// reproduce the observation. The `benign` / suspicious framing lives in
/// [`Ext4Anomaly::note`]: an anomaly is an *observation*, never an assertion of
/// intent.
#[derive(Debug, Clone, PartialEq)]
pub enum Ext4Anomaly {
    /// A backup superblock disagrees with the primary on one or more invariant
    /// fields. ext4 replicates the superblock at group 0 (primary), group 1,
    /// and powers of 3/5/7; the copies are written together and should be
    /// identical. A divergence is consistent with a filesystem resize that did
    /// not propagate, a `tune2fs` edit, on-disk corruption, or deliberate
    /// tampering of one copy.
    SuperblockBackupMismatch {
        /// Block group holding the diverging backup.
        group: u32,
        /// Block number of the backup superblock.
        block: u64,
        /// Field names that differ from the primary (or `unparseable`).
        differences: Vec<String>,
    },

    /// An inode whose deletion time (`dtime`) is set — the kernel stamps `dtime`
    /// when a file is removed. The inode metadata (and, when the block bitmap
    /// still shows its data blocks free, the file content) may be recoverable.
    DeletedInode {
        /// Inode number.
        ino: u64,
        /// File type recorded in the (now deleted) inode.
        file_type: FileType,
        /// File size in bytes.
        size: u64,
        /// Raw 32-bit deletion time (seconds; non-zero by construction here).
        dtime: u32,
        /// Estimated recoverability: fraction of the file's data blocks still
        /// unallocated in the block bitmap, in `[0.0, 1.0]`.
        recoverability: f64,
    },

    /// Non-zero bytes in a file's block slack — the unused tail of its final
    /// allocated block, past the recorded file size. ext4 does not zero this
    /// region on allocation, so it commonly retains fragments of previously
    /// resident data; consistent with leaked residue from prior block use
    /// (often benign) or, rarely, deliberately hidden bytes.
    SlackResidue {
        /// Inode owning the slack.
        ino: u64,
        /// File size in bytes.
        file_size: u64,
        /// Physical block number holding the slack.
        block: u64,
        /// Byte offset within the block where slack begins.
        slack_offset: usize,
        /// Number of non-zero bytes in the slack region.
        nonzero_bytes: usize,
    },

    /// A committed journal (jbd2) transaction whose commit timestamp precedes
    /// that of an earlier-sequenced, already-committed transaction. jbd2 commits
    /// transactions in strictly increasing sequence order, so commit times
    /// should be non-decreasing along that order. A regression is consistent
    /// with a wall-clock change between commits, a journal assembled from
    /// out-of-order sources, or tampering — and is replay-relevant, since
    /// recovery replays by sequence regardless of the timestamp.
    JournalInconsistent {
        /// Sequence number of the later (out-of-order) transaction.
        sequence: u32,
        /// Its commit time (epoch seconds).
        commit_seconds: i64,
        /// Sequence number of the earlier transaction it regressed against.
        prior_sequence: u32,
        /// That earlier transaction's commit time (epoch seconds).
        prior_commit_seconds: i64,
    },
}

impl Ext4Anomaly {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        // Each variant's severity is an independent forensic judgment; two of
        // them currently coincide at Medium, but they are kept as separate arms
        // so either can be re-graded without disturbing the other.
        #[allow(clippy::match_same_arms)]
        match self {
            // A primary/backup superblock divergence is a strong integrity
            // signal, but has benign causes (resize, tune2fs) — Medium, not High.
            Ext4Anomaly::SuperblockBackupMismatch { .. } => Severity::Medium,
            // Recoverable deleted content: Low when the data has been overwritten
            // (nothing to recover), Medium when blocks are still recoverable.
            Ext4Anomaly::DeletedInode { recoverability, .. } => {
                if *recoverability > 0.0 {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            Ext4Anomaly::SlackResidue { .. } => Severity::Low,
            Ext4Anomaly::JournalInconsistent { .. } => Severity::Medium,
        }
    }

    /// Stable machine-readable code (a published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Ext4Anomaly::SuperblockBackupMismatch { .. } => "EXT4-SUPERBLOCK-BACKUP-MISMATCH",
            Ext4Anomaly::DeletedInode { .. } => "EXT4-DELETED-INODE",
            Ext4Anomaly::SlackResidue { .. } => "EXT4-SLACK-RESIDUE",
            Ext4Anomaly::JournalInconsistent { .. } => "EXT4-JOURNAL-INCONSISTENT",
        }
    }

    /// Analytical lens. The keyword classifier in
    /// [`forensicnomicon::report::Category::from_code`] does not recognise these
    /// ext4-specific codes, so each is set explicitly.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            // Primary vs backup field divergence is a structural-integrity concern.
            Ext4Anomaly::SuperblockBackupMismatch { .. } => Category::Integrity,
            // Recoverable deleted/leaked content.
            Ext4Anomaly::DeletedInode { .. } | Ext4Anomaly::SlackResidue { .. } => {
                Category::Residue
            }
            // The journal is the filesystem's temporal record.
            Ext4Anomaly::JournalInconsistent { .. } => Category::History,
        }
    }

    /// Human-readable description (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            Ext4Anomaly::SuperblockBackupMismatch { group, block, differences } => format!(
                "backup superblock in block group {group} (block {block}) disagrees with the primary \
                 on field(s) [{}] — ext4 writes the primary and its backups together, so they should \
                 be identical; a divergence is consistent with a resize that did not propagate, a \
                 tune2fs edit, on-disk corruption, or one copy having been edited",
                differences.join(", ")
            ),
            Ext4Anomaly::DeletedInode { ino, file_type, size, dtime, recoverability } => format!(
                "inode {ino} ({file_type:?}, {size} bytes) has its deletion time set (dtime={dtime}) \
                 — the kernel stamps dtime when a file is removed; {} of its data blocks remain \
                 unallocated, so its content is consistent with being recoverable",
                recoverability_phrase(*recoverability)
            ),
            Ext4Anomaly::SlackResidue { ino, file_size, block, slack_offset, nonzero_bytes } => format!(
                "inode {ino} ({file_size} bytes) has {nonzero_bytes} non-zero byte(s) in the slack of \
                 its final block (physical block {block}, from offset {slack_offset}) — ext4 does not \
                 zero block slack on allocation, so this is consistent with leaked residue from the \
                 block's prior use (often benign) or, rarely, deliberately hidden bytes"
            ),
            Ext4Anomaly::JournalInconsistent {
                sequence,
                commit_seconds,
                prior_sequence,
                prior_commit_seconds,
            } => format!(
                "journal transaction seq {sequence} committed at epoch {commit_seconds}, before \
                 earlier transaction seq {prior_sequence} at epoch {prior_commit_seconds} — jbd2 \
                 commits in increasing sequence order, so commit times should be non-decreasing; a \
                 regression is consistent with a wall-clock change between commits, a journal \
                 assembled from out-of-order sources, or tampering (replay-relevant: recovery replays \
                 by sequence, not by timestamp)"
            ),
        }
    }
}

impl Observation for Ext4Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(Ext4Anomaly::severity(self))
    }
    fn code(&self) -> &'static str {
        Ext4Anomaly::code(self)
    }
    fn note(&self) -> String {
        Ext4Anomaly::note(self)
    }
    fn category(&self) -> Category {
        Ext4Anomaly::category(self)
    }
}

/// Render a recoverability fraction as a short human phrase for notes.
fn recoverability_phrase(recoverability: f64) -> String {
    if recoverability <= 0.0 {
        "none".to_string()
    } else if recoverability >= 1.0 {
        "all".to_string()
    } else {
        format!("{:.0}%", recoverability * 100.0)
    }
}

/// Convert superblock-backup comparisons into findings.
///
/// One [`Ext4Anomaly::SuperblockBackupMismatch`] per backup that does not match
/// the primary; matching backups produce no finding.
#[must_use]
pub fn superblock_findings(comparisons: &[SuperblockComparison]) -> Vec<Ext4Anomaly> {
    comparisons
        .iter()
        .filter(|c| !c.matches_primary)
        .map(|c| Ext4Anomaly::SuperblockBackupMismatch {
            group: c.group,
            block: c.block,
            differences: c.differences.clone(),
        })
        .collect()
}

/// Convert deleted inodes into findings (one [`Ext4Anomaly::DeletedInode`] each).
#[must_use]
pub fn deleted_inode_findings(deleted: &[DeletedInode]) -> Vec<Ext4Anomaly> {
    deleted
        .iter()
        .map(|d| Ext4Anomaly::DeletedInode {
            ino: d.ino,
            file_type: d.file_type,
            size: d.size,
            dtime: d.dtime,
            recoverability: d.recoverability,
        })
        .collect()
}

/// Convert file slack into findings.
///
/// Only slack regions that actually contain non-zero bytes produce a finding —
/// an all-zero tail is the expected, uninteresting case.
#[must_use]
pub fn slack_findings(slacks: &[SlackSpace]) -> Vec<Ext4Anomaly> {
    slacks
        .iter()
        .filter_map(|s| {
            let nonzero = s.data.iter().filter(|&&b| b != 0).count();
            if nonzero == 0 {
                return None;
            }
            Some(Ext4Anomaly::SlackResidue {
                ino: s.ino,
                file_size: s.file_size,
                block: s.block,
                slack_offset: s.slack_offset,
                nonzero_bytes: nonzero,
            })
        })
        .collect()
}

/// Convert journal transactions into findings.
///
/// Surfaces commit-timestamp regressions: jbd2 commits in increasing sequence
/// order, so a transaction whose commit time precedes that of an earlier
/// committed transaction is a replay-relevant inconsistency. Transactions are
/// examined in their parsed (sequence) order; the running maximum commit time
/// is the baseline each transaction is compared against.
#[must_use]
pub fn journal_findings(journal: &Journal) -> Vec<Ext4Anomaly> {
    let mut findings = Vec::new();
    // The running maximum commit instant (seconds, nanoseconds) among the
    // transactions seen so far, with the sequence that set it. Full-precision
    // comparison: a regression that is only visible at sub-second granularity is
    // still a regression.
    let mut max_seen: Option<(u32, i64, u32)> = None;
    for txn in &journal.transactions {
        let now = (txn.commit_seconds, txn.commit_nanoseconds);
        if let Some((prior_seq, prior_secs, prior_nsec)) = max_seen {
            if now < (prior_secs, prior_nsec) {
                findings.push(Ext4Anomaly::JournalInconsistent {
                    sequence: txn.sequence,
                    commit_seconds: txn.commit_seconds,
                    prior_sequence: prior_seq,
                    prior_commit_seconds: prior_secs,
                });
                // A regression does not advance the baseline: subsequent
                // transactions are still compared against the last in-order max.
                continue;
            }
        }
        max_seen = Some((txn.sequence, txn.commit_seconds, txn.commit_nanoseconds));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::forensic::deleted::find_deleted_inodes;
    use crate::forensic::journal::{parse_journal, Journal, JournalMapping, Transaction};
    use crate::forensic::slack::{scan_all_slack, SlackSpace};
    use crate::forensic::superblock_verify::{verify_superblock_backups, SuperblockComparison};
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    // -- trait wiring: code / category / severity are derived, cannot drift --

    #[test]
    fn deleted_inode_maps_to_residue_code() {
        let a = Ext4Anomaly::DeletedInode {
            ino: 21,
            file_type: FileType::RegularFile,
            size: 100,
            dtime: 1,
            recoverability: 0.5,
        };
        assert_eq!(Observation::code(&a), "EXT4-DELETED-INODE");
        assert_eq!(Observation::category(&a), Category::Residue);
        assert_eq!(Observation::severity(&a), Some(Severity::Medium));
        let f = a.to_finding(forensicnomicon::report::Source::default());
        assert_eq!(f.code, "EXT4-DELETED-INODE");
        assert_eq!(f.category, Category::Residue);
    }

    #[test]
    fn overwritten_deleted_inode_is_low() {
        let a = Ext4Anomaly::DeletedInode {
            ino: 21,
            file_type: FileType::RegularFile,
            size: 100,
            dtime: 1,
            recoverability: 0.0,
        };
        assert_eq!(Observation::severity(&a), Some(Severity::Low));
    }

    #[test]
    fn slack_maps_to_residue_code() {
        let a = Ext4Anomaly::SlackResidue {
            ino: 12,
            file_size: 12,
            block: 100,
            slack_offset: 12,
            nonzero_bytes: 3,
        };
        assert_eq!(Observation::code(&a), "EXT4-SLACK-RESIDUE");
        assert_eq!(Observation::category(&a), Category::Residue);
        assert_eq!(Observation::severity(&a), Some(Severity::Low));
    }

    #[test]
    fn superblock_maps_to_integrity_code() {
        let a = Ext4Anomaly::SuperblockBackupMismatch {
            group: 1,
            block: 32768,
            differences: vec!["blocks_count".to_string()],
        };
        assert_eq!(Observation::code(&a), "EXT4-SUPERBLOCK-BACKUP-MISMATCH");
        assert_eq!(Observation::category(&a), Category::Integrity);
        assert_eq!(Observation::severity(&a), Some(Severity::Medium));
        assert!(Observation::note(&a).contains("blocks_count"));
    }

    #[test]
    fn journal_maps_to_history_code() {
        let a = Ext4Anomaly::JournalInconsistent {
            sequence: 3,
            commit_seconds: 100,
            prior_sequence: 2,
            prior_commit_seconds: 200,
        };
        assert_eq!(Observation::code(&a), "EXT4-JOURNAL-INCONSISTENT");
        assert_eq!(Observation::category(&a), Category::History);
        assert_eq!(Observation::severity(&a), Some(Severity::Medium));
    }

    #[test]
    fn every_variant_has_a_consistent_with_note() {
        let variants = [
            Ext4Anomaly::SuperblockBackupMismatch {
                group: 1,
                block: 32768,
                differences: vec!["uuid".to_string()],
            },
            Ext4Anomaly::DeletedInode {
                ino: 21,
                file_type: FileType::RegularFile,
                size: 100,
                dtime: 1,
                recoverability: 0.5,
            },
            Ext4Anomaly::SlackResidue {
                ino: 12,
                file_size: 12,
                block: 100,
                slack_offset: 12,
                nonzero_bytes: 3,
            },
            Ext4Anomaly::JournalInconsistent {
                sequence: 3,
                commit_seconds: 100,
                prior_sequence: 2,
                prior_commit_seconds: 200,
            },
        ];
        for v in &variants {
            let note = Observation::note(v);
            assert!(
                note.contains("consistent with"),
                "{} note must use consistent-with framing: {note}",
                Observation::code(v)
            );
        }
    }

    #[test]
    fn recoverability_phrase_extremes_in_note() {
        let none = Ext4Anomaly::DeletedInode {
            ino: 1,
            file_type: FileType::RegularFile,
            size: 10,
            dtime: 1,
            recoverability: 0.0,
        };
        let all = Ext4Anomaly::DeletedInode {
            ino: 2,
            file_type: FileType::RegularFile,
            size: 10,
            dtime: 1,
            recoverability: 1.0,
        };
        assert!(none.note().contains("none of its data blocks"));
        assert!(all.note().contains("all of its data blocks"));
    }

    // -- conversion functions on synthetic engine outputs --

    #[test]
    fn superblock_findings_only_for_mismatches() {
        let comparisons = vec![
            SuperblockComparison {
                group: 1,
                block: 32768,
                matches_primary: true,
                differences: vec![],
            },
            SuperblockComparison {
                group: 3,
                block: 98304,
                matches_primary: false,
                differences: vec!["uuid".to_string(), "blocks_count".to_string()],
            },
        ];
        let findings = superblock_findings(&comparisons);
        assert_eq!(
            findings.len(),
            1,
            "only the mismatching backup yields a finding"
        );
        match &findings[0] {
            Ext4Anomaly::SuperblockBackupMismatch {
                group, differences, ..
            } => {
                assert_eq!(*group, 3);
                assert_eq!(differences.len(), 2);
            }
            other => panic!("expected SuperblockBackupMismatch, got {other:?}"),
        }
    }

    #[test]
    fn slack_findings_skip_all_zero_slack() {
        let zero = SlackSpace {
            ino: 10,
            file_size: 5,
            block: 50,
            slack_offset: 5,
            data: vec![0u8; 4091],
        };
        let nonzero = SlackSpace {
            ino: 11,
            file_size: 5,
            block: 51,
            slack_offset: 5,
            data: vec![0, 0, 0x41, 0x42, 0],
        };
        let findings = slack_findings(&[zero, nonzero]);
        assert_eq!(findings.len(), 1, "only non-zero slack yields a finding");
        match &findings[0] {
            Ext4Anomaly::SlackResidue {
                ino, nonzero_bytes, ..
            } => {
                assert_eq!(*ino, 11);
                assert_eq!(*nonzero_bytes, 2);
            }
            other => panic!("expected SlackResidue, got {other:?}"),
        }
    }

    fn txn(sequence: u32, commit_seconds: i64) -> Transaction {
        Transaction {
            sequence,
            commit_seconds,
            commit_nanoseconds: 0,
            mappings: Vec::<JournalMapping>::new(),
            revoked_blocks: Vec::new(),
        }
    }

    fn journal_of(transactions: Vec<Transaction>) -> Journal {
        Journal {
            block_size: 4096,
            total_blocks: 1024,
            first_block: 1,
            transactions,
            is_64bit: true,
            has_csum_v3: false,
        }
    }

    #[test]
    fn journal_findings_flag_timestamp_regression() {
        // seq 2 @ t=200, seq 3 @ t=150 (earlier) -> one regression finding.
        let j = journal_of(vec![txn(2, 200), txn(3, 150)]);
        let findings = journal_findings(&j);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Ext4Anomaly::JournalInconsistent {
                sequence,
                prior_sequence,
                commit_seconds,
                prior_commit_seconds,
            } => {
                assert_eq!(*sequence, 3);
                assert_eq!(*prior_sequence, 2);
                assert_eq!(*commit_seconds, 150);
                assert_eq!(*prior_commit_seconds, 200);
            }
            other => panic!("expected JournalInconsistent, got {other:?}"),
        }
    }

    #[test]
    fn journal_findings_none_when_monotonic() {
        let j = journal_of(vec![txn(2, 100), txn(3, 100), txn(4, 200)]);
        assert!(
            journal_findings(&j).is_empty(),
            "non-decreasing commit times are clean"
        );
    }

    // -- real-image cross-check (forensic.img; skips cleanly if absent) --

    #[test]
    fn real_image_deleted_inodes_match_tsk() {
        let mut reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        let findings = deleted_inode_findings(&deleted);
        // TSK `fls -rd forensic.img` lists deleted inodes 21 and 22.
        let inos: Vec<u64> = findings
            .iter()
            .filter_map(|f| match f {
                Ext4Anomaly::DeletedInode { ino, .. } => Some(*ino),
                _ => None,
            })
            .collect();
        assert!(
            inos.contains(&21),
            "expected deleted inode 21, got {inos:?}"
        );
        assert!(
            inos.contains(&22),
            "expected deleted inode 22, got {inos:?}"
        );
        for f in &findings {
            assert_eq!(Observation::code(f), "EXT4-DELETED-INODE");
            assert!(Observation::severity(f).is_some());
        }
    }

    #[test]
    fn real_image_slack_residue_present() {
        let mut reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        let slacks = scan_all_slack(&mut reader).unwrap();
        let findings = slack_findings(&slacks);
        // Every emitted finding must be a non-zero-slack residue finding.
        for f in &findings {
            match f {
                Ext4Anomaly::SlackResidue { nonzero_bytes, .. } => assert!(*nonzero_bytes > 0),
                other => panic!("expected SlackResidue, got {other:?}"),
            }
        }
    }

    #[test]
    fn real_image_journal_is_monotonic_so_no_findings() {
        // The engine parses forensic.img's journal as two committed transactions,
        // seq 2 @ 1774998586.843380012 then seq 3 @ 1774998586.873380012 — commit
        // instants increase with sequence (verified against the engine output;
        // TSK `jls` additionally lists stale/unallocated commit blocks that the
        // engine does not treat as committed transactions). A monotonic journal
        // is the clean case, so the adapter emits NO EXT4-JOURNAL-INCONSISTENT
        // finding here. (The regression-detection path is exercised by the
        // synthetic `journal_findings_flag_timestamp_regression` test above.)
        let mut reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        let journal = parse_journal(&mut reader).unwrap();
        let findings = journal_findings(&journal);
        assert!(
            findings.is_empty(),
            "forensic.img journal commit times are monotonic; expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn real_image_superblock_single_group_no_backups() {
        // forensic.img is a single block group (TSK fsstat: Number of Block
        // Groups: 1), so there are no backup superblocks to compare and the
        // adapter emits no superblock findings — the correct empty result, not a
        // bootstrap failure (the comparison list itself is empty).
        let mut reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        let comparisons = verify_superblock_backups(&mut reader).unwrap();
        let findings = superblock_findings(&comparisons);
        for f in &findings {
            assert_eq!(Observation::code(f), "EXT4-SUPERBLOCK-BACKUP-MISMATCH");
        }
    }
}
