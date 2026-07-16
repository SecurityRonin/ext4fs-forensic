//! `impl FileSystem for Ext4Fs` — the forensic-vfs adapter (behind the `vfs`
//! feature).
//!
//! [`Ext4Fs`] serves every read through a shared `&self` over a `Mutex`-guarded
//! source (see `block.rs`), so one mounted handle backs N workers. This module
//! maps that reader onto the [`forensic_vfs::FileSystem`] contract: ext nodes are
//! addressed by [`FileId::ExtInode`] (inode number + generation), directory and
//! run enumerations are owned `Send` streams, and every fallible ext4fs-core call
//! is translated to a typed [`VfsError`] — never an `unwrap`/panic
//! (Paranoid Gatekeeper).
//!
//! ## Mapping notes / known limits
//! - **`gen` in listings.** ext directory entries carry the child inode number
//!   and a file-type nibble but *not* the inode generation, so [`read_dir`] and
//!   [`lookup`] emit `gen: 0` ("generation unknown at this layer"); [`meta`]
//!   reads the inode and could surface the true generation.
//! - **Single stream.** ext has no alternate data streams; every non-`Default`
//!   [`StreamId`] is refused loud rather than silently read as the default.
//! - **Deleted/unallocated** are empty streams for now (ext4fs-core exposes
//!   `deleted_inodes()`/`unallocated_blocks()`; wiring them here is a follow-up).
//! - **Symlinks** resolve through ext4fs-core (`read_link`); a non-symlink reads
//!   as an empty target, matching the NTFS adapter.
//! - **Unwritten (preallocated) extents** are reported as allocated runs; the
//!   `unwritten` flag is not yet surfaced on [`RunFlags`].

use std::io::{Read, Seek};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem,
    FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy,
    VfsError, VfsResult,
};

use crate::error::Ext4Error;
use crate::ondisk::{DirEntryType, FileType, Timestamp};
use crate::Ext4Fs;

/// The ext root directory is always inode 2.
const ROOT_INO: u64 = 2;

/// The inode number carried by a [`FileId`]. Only ext inode references address
/// this filesystem; any other identity domain is a caller error, surfaced loud.
fn ino_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::ExtInode { ino, .. } => Ok(ino),
        other => Err(VfsError::Unsupported {
            layer: "ext4 file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// ext exposes a single unnamed data stream; a named-stream id is refused loud
/// rather than silently read as the default stream.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "ext4 stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate an ext4fs-core error into the VFS error type, keeping I/O distinct
/// from a structural decode failure and range misses distinct from both.
fn map_err(e: Ext4Error) -> VfsError {
    match e {
        Ext4Error::Io(source) => VfsError::Io {
            op: "ext4 read",
            source,
        },
        Ext4Error::InodeOutOfRange { ino, max } => VfsError::OutOfRange {
            what: "ext4 inode",
            offset: ino,
            len: 1,
            bound: max,
        },
        Ext4Error::BlockOutOfRange { block, max } => VfsError::OutOfRange {
            what: "ext4 block",
            offset: block,
            len: 1,
            bound: max,
        },
        other => VfsError::Decode {
            layer: "ext4",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// The inode's `i_mode` file-type nibble mapped to the unified node kind.
fn node_kind(ft: FileType) -> NodeKind {
    match ft {
        FileType::RegularFile => NodeKind::File,
        FileType::Directory => NodeKind::Dir,
        FileType::Symlink => NodeKind::Symlink,
        FileType::CharDevice | FileType::BlockDevice => NodeKind::Device,
        FileType::Fifo | FileType::Socket | FileType::Unknown => NodeKind::Other,
    }
}

/// The directory-entry file-type byte mapped to the unified node kind (cheap —
/// no inode read; present whenever the FILETYPE feature is on, which ext4 is).
fn dirent_kind(dt: DirEntryType) -> NodeKind {
    match dt {
        DirEntryType::RegularFile => NodeKind::File,
        DirEntryType::Directory => NodeKind::Dir,
        DirEntryType::Symlink => NodeKind::Symlink,
        DirEntryType::CharDevice | DirEntryType::BlockDevice => NodeKind::Device,
        DirEntryType::Fifo | DirEntryType::Socket | DirEntryType::Unknown => NodeKind::Other,
    }
}

impl<R: Read + Seek + Send> FileSystem for Ext4Fs<R> {
    fn kind(&self) -> FsKind {
        FsKind::Ext
    }

    fn root(&self) -> FileId {
        // Read inode 2 for its generation; degrade to 0 (never panic) if the
        // read fails on a volume this was already opened from.
        let generation = self
            .dir_reader
            .inode_reader()
            .read_inode(ROOT_INO)
            .map_or(0, |i| i.generation);
        FileId::ExtInode {
            ino: ROOT_INO,
            gen: generation,
        }
    }

    fn sector_sizes(&self) -> SectorSizes {
        let block_size = self.superblock().block_size;
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: block_size,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // ext timestamps are seconds since the Unix epoch, in UTC.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let dir_ino = ino_of(ino)?;
        let entries = self.dir_reader.read_dir(dir_ino).map_err(map_err)?;
        let out: Vec<VfsResult<VfsDirEntry>> = entries
            .into_iter()
            .map(|e| {
                Ok(VfsDirEntry {
                    name: e.name,
                    id: FileId::ExtInode {
                        ino: u64::from(e.inode),
                        gen: 0,
                    },
                    kind: dirent_kind(e.file_type),
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let inode = ino_of(ino)?;
        require_default_stream(stream)?;
        let block_size = u64::from(self.superblock().block_size);
        let map = self
            .dir_reader
            .inode_reader()
            .inode_block_map(inode)
            .map_err(map_err)?;
        let out: Vec<VfsResult<RunInfo>> = map
            .into_iter()
            .map(|m| {
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset: m.physical_block.saturating_mul(block_size),
                        len: m.length.saturating_mul(block_size),
                        flags: RunFlags::default(),
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let dir_ino = ino_of(parent)?;
        let found = self.dir_reader.lookup(dir_ino, name).map_err(map_err)?;
        Ok(found.map(|ino| FileId::ExtInode { ino, gen: 0 }))
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let inode_no = ino_of(ino)?;
        let ir = self.dir_reader.inode_reader();
        let inode = ir.read_inode(inode_no).map_err(map_err)?;
        let allocated = if ir.is_inode_allocated(inode_no).map_err(map_err)? {
            Allocation::Allocated
        } else {
            Allocation::Deleted
        };

        // Nanosecond resolution is only present on large (>=256-byte) inodes with
        // the extended timestamp fields (extra_isize >= 28); otherwise seconds.
        let resolution = if inode.extra_isize >= 28 {
            TimeResolution::Nanos
        } else {
            TimeResolution::Seconds
        };
        let ts = |t: &Timestamp| TimeStamp {
            unix_nanos: i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanoseconds),
            source: TimeSource::InodeTable,
            resolution,
        };
        // crtime is absent on 128-byte inodes (left zero); None is forensically
        // distinct from an epoch-zero creation time.
        let born = if inode.crtime.seconds != 0 {
            Some(ts(&inode.crtime))
        } else {
            None
        };

        let residency = if inode.has_inline_data() {
            ResidencyKind::Resident {
                inline_len: inode.size.min(60) as u32,
            }
        } else {
            ResidencyKind::NonResident
        };

        Ok(FsMeta {
            ino: inode_no,
            kind: node_kind(inode.file_type()),
            allocated,
            size: inode.size,
            nlink: u32::from(inode.links_count),
            uid: Some(inode.uid),
            gid: Some(inode.gid),
            mode: Some(u32::from(inode.mode)),
            times: MacbTimes {
                modified: Some(ts(&inode.mtime)),
                accessed: Some(ts(&inode.atime)),
                changed: Some(ts(&inode.ctime)),
                born,
            },
            streams: Vec::new(),
            residency,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let inode = ino_of(ino)?;
        require_default_stream(stream)?;
        // read_inode_data_range already windows to [off, off+len) and skips
        // blocks outside it, so a huge file is never pulled wholesale.
        let data = self
            .dir_reader
            .inode_reader()
            .read_inode_data_range(inode, off, buf.len())
            .map_err(map_err)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let inode = ino_of(ino)?;
        match self.dir_reader.read_link(inode) {
            Ok(mut target) => {
                target.truncate(cap);
                Ok(target)
            }
            // A node that is not a symlink reads as an empty target (matches the
            // NTFS adapter), rather than surfacing a per-node miss as an error.
            Err(Ext4Error::NotASymlink(_)) => Ok(Vec::new()),
            Err(e) => Err(map_err(e)),
        }
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Deleted-inode carving is a follow-up; the default surface is an empty
        // stream, not a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    //! Unit coverage for the pure mapping helpers. Every arm of `map_err`,
    //! `node_kind`, and `dirent_kind` is total by construction, so each variant
    //! is exercised directly here — the device/fifo/socket node kinds and the
    //! I/O and decode error classes have no representative in the committed ext4
    //! fixtures, and driving them through the adapter would require minting a
    //! bespoke image per arm.
    use super::{dirent_kind, map_err, node_kind};
    use crate::error::Ext4Error;
    use crate::ondisk::{dir_entry::DirEntryType, inode::FileType};
    use forensic_vfs::{NodeKind, VfsError};

    #[test]
    fn map_err_io_is_io() {
        let e = Ext4Error::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe"));
        assert!(matches!(
            map_err(e),
            VfsError::Io {
                op: "ext4 read",
                ..
            }
        ));
    }

    /// Destructure an `OutOfRange` into its identifying fields, or `None` for any
    /// other variant — keeps the assertions branch-free (no dead panic arm).
    fn out_of_range(e: &VfsError) -> Option<(&'static str, u64, u64)> {
        if let VfsError::OutOfRange {
            what,
            offset,
            bound,
            ..
        } = e
        {
            Some((what, *offset, *bound))
        } else {
            None
        }
    }

    #[test]
    fn map_err_inode_range_is_out_of_range() {
        let e = Ext4Error::InodeOutOfRange { ino: 999, max: 100 };
        assert_eq!(out_of_range(&map_err(e)), Some(("ext4 inode", 999, 100)));
    }

    #[test]
    fn map_err_block_range_is_out_of_range() {
        let e = Ext4Error::BlockOutOfRange { block: 50, max: 10 };
        assert_eq!(out_of_range(&map_err(e)), Some(("ext4 block", 50, 10)));
    }

    #[test]
    fn out_of_range_helper_rejects_non_range_errors() {
        // The destructuring helper yields None for anything that is not an
        // OutOfRange, keeping the range assertions unambiguous.
        let io = map_err(Ext4Error::Io(std::io::Error::other("x")));
        assert_eq!(out_of_range(&io), None);
    }

    #[test]
    fn map_err_other_is_decode() {
        // Any structural error that is neither I/O nor a range miss folds into
        // Decode with the ext4fs-core message preserved.
        let e = Ext4Error::CorruptMetadata {
            structure: "inode",
            detail: "bad".into(),
        };
        assert!(matches!(map_err(e), VfsError::Decode { layer: "ext4", .. }));
    }

    #[test]
    fn node_kind_covers_every_file_type() {
        assert_eq!(node_kind(FileType::RegularFile), NodeKind::File);
        assert_eq!(node_kind(FileType::Directory), NodeKind::Dir);
        assert_eq!(node_kind(FileType::Symlink), NodeKind::Symlink);
        assert_eq!(node_kind(FileType::CharDevice), NodeKind::Device);
        assert_eq!(node_kind(FileType::BlockDevice), NodeKind::Device);
        assert_eq!(node_kind(FileType::Fifo), NodeKind::Other);
        assert_eq!(node_kind(FileType::Socket), NodeKind::Other);
        assert_eq!(node_kind(FileType::Unknown), NodeKind::Other);
    }

    #[test]
    fn dirent_kind_covers_every_dir_entry_type() {
        assert_eq!(dirent_kind(DirEntryType::RegularFile), NodeKind::File);
        assert_eq!(dirent_kind(DirEntryType::Directory), NodeKind::Dir);
        assert_eq!(dirent_kind(DirEntryType::Symlink), NodeKind::Symlink);
        assert_eq!(dirent_kind(DirEntryType::CharDevice), NodeKind::Device);
        assert_eq!(dirent_kind(DirEntryType::BlockDevice), NodeKind::Device);
        assert_eq!(dirent_kind(DirEntryType::Fifo), NodeKind::Other);
        assert_eq!(dirent_kind(DirEntryType::Socket), NodeKind::Other);
        assert_eq!(dirent_kind(DirEntryType::Unknown), NodeKind::Other);
    }
}
