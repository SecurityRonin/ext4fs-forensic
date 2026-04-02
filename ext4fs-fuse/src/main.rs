#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use ext4fs::Ext4Fs;
use forensic_mount::{
    ForensicFs, FsBlockRange, FsDirEntry, FsDeletedInode, FsEventType, FsFileType,
    FsMetadata, FsRecoveryResult, FsResult, FsTimestamp, FsTimelineEvent, FsTransaction,
};
use std::fs::File;

/// Wrapper to implement ForensicFs for Ext4Fs<File>.
struct Ext4ForensicFs {
    fs: Ext4Fs<File>,
}

impl ForensicFs for Ext4ForensicFs {
    fn root_ino(&self) -> u64 {
        2 // ext4 root is always inode 2
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let entries = self.fs.read_dir_by_ino(ino).map_err(map_err)?;
        Ok(entries
            .iter()
            .map(|e| FsDirEntry {
                inode: e.inode as u64,
                name: e.name.clone(),
                file_type: map_dir_entry_type(e.file_type),
            })
            .collect())
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.fs.lookup_by_ino(parent_ino, name).map_err(map_err)
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let inode = self.fs.inode(ino).map_err(map_err)?;
        let allocated = self.fs.is_inode_allocated(ino).unwrap_or(false);
        Ok(FsMetadata {
            ino,
            file_type: map_file_type(inode.file_type()),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            links_count: inode.links_count,
            atime: map_ts(&inode.atime),
            mtime: map_ts(&inode.mtime),
            ctime: map_ts(&inode.ctime),
            crtime: map_ts(&inode.crtime),
            allocated,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        self.fs.read_inode_data(ino).map_err(map_err)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        self.fs
            .read_inode_data_range(ino, offset, len as usize)
            .map_err(map_err)
    }

    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        self.fs.read_link_by_ino(ino).map_err(map_err)
    }

    fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> {
        let deleted = self.fs.deleted_inodes().map_err(map_err)?;
        Ok(deleted
            .into_iter()
            .map(|d| FsDeletedInode {
                ino: d.ino,
                file_type: map_file_type(d.file_type),
                size: d.size,
                dtime: d.dtime,
                recoverability: d.recoverability,
            })
            .collect())
    }

    fn recover_file(&mut self, ino: u64) -> FsResult<FsRecoveryResult> {
        let r = self.fs.recover_file(ino).map_err(map_err)?;
        let pct = r.recovery_percentage();
        Ok(FsRecoveryResult {
            ino,
            data: r.data,
            expected_size: r.expected_size,
            recovered_bytes: r.recovered_size,
            recovery_percentage: pct,
        })
    }

    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        let events = self.fs.timeline().map_err(map_err)?;
        Ok(events
            .into_iter()
            .map(|e| FsTimelineEvent {
                timestamp: map_ts(&e.timestamp),
                event_type: match e.event_type {
                    ext4fs::forensic::EventType::Created => FsEventType::Created,
                    ext4fs::forensic::EventType::Modified => FsEventType::Modified,
                    ext4fs::forensic::EventType::Accessed => FsEventType::Accessed,
                    ext4fs::forensic::EventType::Changed => FsEventType::Changed,
                    ext4fs::forensic::EventType::Deleted => FsEventType::Deleted,
                    ext4fs::forensic::EventType::Mounted => FsEventType::Mounted,
                },
                inode: e.inode,
                size: e.size,
                uid: e.uid,
                gid: e.gid,
            })
            .collect())
    }

    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        let blocks = self.fs.unallocated_blocks().map_err(map_err)?;
        Ok(blocks
            .into_iter()
            .map(|b| FsBlockRange {
                start: b.start,
                length: b.length,
            })
            .collect())
    }

    fn read_unallocated(&mut self, range: &FsBlockRange) -> FsResult<Vec<u8>> {
        let ext4_range = ext4fs::forensic::BlockRange {
            start: range.start,
            length: range.length,
        };
        self.fs.read_unallocated(&ext4_range).map_err(map_err)
    }

    fn journal_transactions(&mut self) -> FsResult<Vec<FsTransaction>> {
        let journal = self.fs.journal().map_err(map_err)?;
        Ok(journal
            .transactions
            .into_iter()
            .map(|t| FsTransaction {
                sequence: t.sequence as u64,
                commit_seconds: t.commit_seconds as u64,
                commit_nanoseconds: t.commit_nanoseconds,
            })
            .collect())
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        let sb = self.fs.superblock();
        Ok(serde_json::json!({
            "filesystem": "ext4",
            "label": sb.label(),
            "uuid": sb.uuid_string(),
            "block_size": sb.block_size,
            "blocks_count": sb.blocks_count,
            "inodes_count": sb.inodes_count,
        }))
    }

    fn block_size(&self) -> u64 {
        self.fs.superblock().block_size as u64
    }
}

// --- Type mapping helpers ---

fn map_err(e: ext4fs::error::Ext4Error) -> forensic_mount::FsError {
    forensic_mount::FsError::Other(e.to_string())
}

fn map_file_type(ft: ext4fs::ondisk::FileType) -> FsFileType {
    match ft {
        ext4fs::ondisk::FileType::RegularFile => FsFileType::RegularFile,
        ext4fs::ondisk::FileType::Directory => FsFileType::Directory,
        ext4fs::ondisk::FileType::Symlink => FsFileType::Symlink,
        ext4fs::ondisk::FileType::CharDevice => FsFileType::CharDevice,
        ext4fs::ondisk::FileType::BlockDevice => FsFileType::BlockDevice,
        ext4fs::ondisk::FileType::Fifo => FsFileType::Fifo,
        ext4fs::ondisk::FileType::Socket => FsFileType::Socket,
        ext4fs::ondisk::FileType::Unknown => FsFileType::Unknown,
    }
}

fn map_dir_entry_type(dt: ext4fs::ondisk::DirEntryType) -> FsFileType {
    match dt {
        ext4fs::ondisk::DirEntryType::RegularFile => FsFileType::RegularFile,
        ext4fs::ondisk::DirEntryType::Directory => FsFileType::Directory,
        ext4fs::ondisk::DirEntryType::Symlink => FsFileType::Symlink,
        ext4fs::ondisk::DirEntryType::CharDevice => FsFileType::CharDevice,
        ext4fs::ondisk::DirEntryType::BlockDevice => FsFileType::BlockDevice,
        ext4fs::ondisk::DirEntryType::Fifo => FsFileType::Fifo,
        ext4fs::ondisk::DirEntryType::Socket => FsFileType::Socket,
        ext4fs::ondisk::DirEntryType::Unknown => FsFileType::Unknown,
    }
}

fn map_ts(ts: &ext4fs::ondisk::Timestamp) -> FsTimestamp {
    FsTimestamp {
        seconds: ts.seconds,
        nanoseconds: ts.nanoseconds,
    }
}

// --- CLI ---

#[derive(Parser)]
#[command(name = "ext4fs-fuse", about = "Forensic FUSE mount for ext4 images")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an ext4 image
    Mount {
        /// Path to ext4 image file
        image: String,
        /// Mount point directory
        mountpoint: String,
        /// Session directory for COW overlay persistence
        #[arg(long)]
        session: Option<String>,
        /// Resume a previous session
        #[arg(long)]
        resume: bool,
        /// Known-good hash database files for evidence/ filtering
        #[arg(long = "filter-db")]
        filter_dbs: Vec<String>,
        /// Run as a background daemon
        #[arg(long)]
        daemon: bool,
    },
    /// Export session for sharing
    ExportSession {
        /// Session directory to export
        session_dir: String,
        /// Output tarball path
        #[arg(long)]
        output: String,
    },
    /// Import a session from tarball
    ImportSession {
        /// Tarball to import
        tarball: String,
        /// Session directory to extract to
        #[arg(long)]
        session: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mount {
            image,
            mountpoint,
            session,
            resume,
            filter_dbs: _,
            daemon,
        } => {
            let file = File::open(&image).unwrap_or_else(|e| {
                eprintln!("Cannot open {image}: {e}");
                std::process::exit(1);
            });
            let ext4 = Ext4Fs::open(file).unwrap_or_else(|e| {
                eprintln!("Cannot parse ext4: {e}");
                std::process::exit(1);
            });
            let fs = Box::new(Ext4ForensicFs { fs: ext4 });

            let session_mgr = session.map(|dir| {
                let session_path = std::path::Path::new(&dir);
                if resume {
                    forensic_mount::session::Session::resume(session_path, std::path::Path::new(&image))
                        .unwrap_or_else(|e| { eprintln!("Cannot resume session: {e}"); std::process::exit(1); })
                } else {
                    forensic_mount::session::Session::create(session_path, std::path::Path::new(&image))
                        .unwrap_or_else(|e| { eprintln!("Cannot create session: {e}"); std::process::exit(1); })
                }
            });

            let options = forensic_mount::MountOptions {
                read_only: session_mgr.is_none(),
                daemon,
                fs_name: "ext4fs-fuse".to_string(),
            };

            eprintln!("Mounting {image} at {mountpoint}");
            forensic_mount::mount(fs, std::path::Path::new(&mountpoint), session_mgr, &options)
                .unwrap_or_else(|e| {
                    eprintln!("Mount failed: {e}");
                    std::process::exit(1);
                });
        }
        Commands::ExportSession {
            session_dir,
            output,
        } => {
            forensic_mount::session::export_session(
                std::path::Path::new(&session_dir),
                std::path::Path::new(&output),
            )
            .unwrap_or_else(|e| {
                eprintln!("Export failed: {e}");
                std::process::exit(1);
            });
            eprintln!("Session exported to {output}");
        }
        Commands::ImportSession { tarball, session } => {
            forensic_mount::session::import_session(
                std::path::Path::new(&tarball),
                std::path::Path::new(&session),
            )
            .unwrap_or_else(|e| {
                eprintln!("Import failed: {e}");
                std::process::exit(1);
            });
            eprintln!("Session imported to {session}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_forensic_fs() -> Option<Ext4ForensicFs> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let file = File::open(path).ok()?;
        let ext4 = Ext4Fs::open(file).ok()?;
        Some(Ext4ForensicFs { fs: ext4 })
    }

    #[test]
    fn root_ino_is_2() {
        let fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn read_dir_root() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let entries = fs.read_dir(2).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
    }

    #[test]
    fn lookup_hello_txt() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let result = fs.lookup(2, b"hello.txt").unwrap();
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn lookup_nonexistent() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let result = fs.lookup(2, b"no_such_file.xyz").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn metadata_root() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let meta = fs.metadata(2).unwrap();
        assert_eq!(meta.ino, 2);
        assert_eq!(meta.file_type, FsFileType::Directory);
        assert!(meta.allocated);
        assert!(meta.links_count >= 2);
    }

    #[test]
    fn metadata_hello_txt() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let meta = fs.metadata(ino).unwrap();
        assert_eq!(meta.file_type, FsFileType::RegularFile);
        assert!(meta.size > 0);
    }

    #[test]
    fn read_file_hello_txt() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file(ino).unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(text.contains("Hello"));
    }

    #[test]
    fn read_file_range_hello_txt() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file_range(ino, 0, 5).unwrap();
        assert_eq!(&data, b"Hello");
    }

    #[test]
    fn read_link_abs_link() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ino = fs.lookup(2, b"abs-link").unwrap().unwrap();
        let target = fs.read_link(ino).unwrap();
        assert_eq!(String::from_utf8_lossy(&target), "/hello.txt");
    }

    #[test]
    fn deleted_inodes_returns_entries() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let deleted = fs.deleted_inodes().unwrap();
        assert!(deleted.len() >= 2);
        let inos: Vec<u64> = deleted.iter().map(|d| d.ino).collect();
        assert!(inos.contains(&21));
        assert!(inos.contains(&22));
    }

    #[test]
    fn recover_file_deleted() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let result = fs.recover_file(21).unwrap();
        assert_eq!(result.ino, 21);
    }

    #[test]
    fn timeline_has_events() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let events = fs.timeline().unwrap();
        assert!(!events.is_empty());
        let has_created = events.iter().any(|e| e.event_type == FsEventType::Created);
        let has_deleted = events.iter().any(|e| e.event_type == FsEventType::Deleted);
        assert!(has_created);
        assert!(has_deleted);
    }

    #[test]
    fn unallocated_blocks_returns_ranges() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ranges = fs.unallocated_blocks().unwrap();
        assert!(!ranges.is_empty());
    }

    #[test]
    fn read_unallocated_returns_data() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ranges = fs.unallocated_blocks().unwrap();
        let data = fs.read_unallocated(&ranges[0]).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn journal_transactions_returns_entries() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let txns = fs.journal_transactions().unwrap();
        assert!(!txns.is_empty());
        for t in &txns {
            assert!(t.sequence > 0);
        }
    }

    #[test]
    fn fs_info_returns_json() {
        let fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let info = fs.fs_info().unwrap();
        assert_eq!(info["filesystem"], "ext4");
        assert!(info["block_size"].as_u64().unwrap() > 0);
    }

    #[test]
    fn block_size_is_4096() {
        let fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert_eq!(fs.block_size(), 4096);
    }

    #[test]
    fn dir_entries_have_correct_file_types() {
        let mut fs = match open_forensic_fs() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let entries = fs.read_dir(2).unwrap();
        let hello = entries.iter().find(|e| e.name_str() == "hello.txt").unwrap();
        assert_eq!(hello.file_type, FsFileType::RegularFile);
        let subdir = entries.iter().find(|e| e.name_str() == "subdir").unwrap();
        assert_eq!(subdir.file_type, FsFileType::Directory);
    }
}
