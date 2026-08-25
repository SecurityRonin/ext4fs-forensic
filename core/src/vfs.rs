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
//!   and a file-type nibble but *not* the inode generation, so `read_dir` and
//!   `lookup` emit `gen: 0` ("generation unknown at this layer"); `meta`
//!   reads the inode and could surface the true generation.
//! - **Single stream.** ext has no alternate data streams; every non-`Default`
//!   [`StreamId`] is refused loud rather than silently read as the default.
//! - **Deleted** is an empty stream for now; carving deleted inodes here is a
//!   follow-up. **Unallocated** enumerates free-block runs from the per-group
//!   block bitmaps (a `BLOCK_UNINIT` group is reported wholly free without a
//!   bitmap read).
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
use crate::ondisk::{DirEntryType, FileType, GroupDescFlags, Timestamp};
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

/// One block group's allocation bitmap for the unallocated-extent walk.
/// `bitmap == None` encodes `BLOCK_UNINIT`: the group's data blocks are all free
/// without an on-disk bitmap to read. `first_block` is the absolute block number
/// of bit 0; `blocks_in_group` bounds the walk (the partial last group is short).
struct GroupBitmap<'a> {
    bitmap: Option<&'a [u8]>,
    first_block: u64,
    blocks_in_group: u64,
}

/// Maximal runs of consecutive free (0) bits in an ext4 block bitmap, over bits
/// `0..blocks_in_group`, returned as `(start_bit, run_len)`. Bit `i` lives in
/// byte `i / 8`, LSB first (ext4 convention); a `1` bit marks an allocated block.
/// A byte beyond the slice is treated as fully allocated, so a truncated bitmap
/// can never fabricate free runs.
fn free_runs(bitmap: &[u8], blocks_in_group: u64) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut run_start: Option<u64> = None;
    for bit in 0..blocks_in_group {
        let allocated = match bitmap.get((bit / 8) as usize) {
            Some(byte) => (byte >> (bit % 8)) & 1 == 1,
            None => true, // a byte past the slice is conservatively allocated
        };
        if allocated {
            if let Some(start) = run_start.take() {
                runs.push((start, bit - start));
            }
        } else if run_start.is_none() {
            run_start = Some(bit);
        }
    }
    if let Some(start) = run_start {
        runs.push((start, blocks_in_group - start));
    }
    runs
}

/// One retained block group's bitmap-read plan: where its data blocks live and
/// which block holds its allocation bitmap. `bitmap_block == None` is a
/// `BLOCK_UNINIT` group — all data blocks free, with no on-disk bitmap to read.
struct GroupPlan {
    first_block: u64,
    blocks_in_group: u64,
    bitmap_block: Option<u64>,
}

/// Plan each retained block group's bitmap read — a pure pass over the group
/// descriptors so every group-selection branch is exercised without a bespoke
/// image. `descriptors` carries each group's `(is_block_uninit, block_bitmap)`
/// in group order; group `g`'s data blocks span
/// `[first_block, first_block + blocks_in_group)`, where `blocks_in_group` is
/// the group size clamped to the tail past `blocks_count`. A group with no data
/// blocks (`blocks_in_group == 0`, the empty tail) is dropped; a `BLOCK_UNINIT`
/// group plans a `None` bitmap (all free); every other group plans a read of its
/// bitmap block. The actual read (and its loud failure) stays in the caller.
fn plan_group_bitmaps(
    descriptors: &[(bool, u64)],
    first_data_block: u64,
    blocks_per_group: u64,
    blocks_count: u64,
) -> Vec<GroupPlan> {
    // Group g's bitmap bit 0 is block `first_data_block + g * blocks_per_group`.
    descriptors
        .iter()
        .enumerate()
        .filter_map(|(g, &(is_block_uninit, block_bitmap))| {
            let first_block =
                first_data_block.saturating_add((g as u64).saturating_mul(blocks_per_group));
            let blocks_in_group = blocks_count
                .saturating_sub(first_block)
                .min(blocks_per_group);
            // The empty tail past `blocks_count` contributes no data blocks.
            (blocks_in_group > 0).then_some(GroupPlan {
                first_block,
                blocks_in_group,
                bitmap_block: if is_block_uninit {
                    None
                } else {
                    Some(block_bitmap)
                },
            })
        })
        .collect()
}

/// One retained group's owned bitmap plus its `(first_block, blocks_in_group)`
/// geometry. A `None` bitmap is a `BLOCK_UNINIT` group (all data blocks free,
/// no on-disk bitmap to read).
type OwnedGroupBitmap = (Option<Vec<u8>>, u64, u64);

/// Emit each group's free-block runs as absolute-offset [`ByteRun`]s. The
/// absolute block of group-relative bit `i` is `group.first_block + i`; its byte
/// offset is `block * block_size`.
fn unallocated_runs(groups: &[GroupBitmap<'_>], block_size: u64) -> Vec<ByteRun> {
    let mut out = Vec::new();
    for g in groups {
        // A `None` bitmap is BLOCK_UNINIT: the whole (bounded) group is free.
        let group_runs = match g.bitmap {
            Some(bm) => free_runs(bm, g.blocks_in_group),
            None if g.blocks_in_group > 0 => vec![(0, g.blocks_in_group)],
            None => Vec::new(),
        };
        for (start_bit, len) in group_runs {
            let first_block = g.first_block.saturating_add(start_bit);
            out.push(ByteRun {
                image_offset: first_block.saturating_mul(block_size),
                len: len.saturating_mul(block_size),
                flags: RunFlags::default(),
            });
        }
    }
    out
}

impl<R: Read + Seek + Send> FileSystem for Ext4Fs<R> {
    fn kind(&self) -> FsKind {
        FsKind::EXT
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
        let br = self.dir_reader.inode_reader().block_reader();
        let sb = br.superblock();
        let block_size = u64::from(sb.block_size);
        let blocks_per_group = u64::from(sb.blocks_per_group);
        let blocks_count = sb.blocks_count;
        // Bit 0 of group g's bitmap is block first_data_block + g*blocks_per_group.
        let first_data_block = u64::from(sb.first_data_block);

        // Which groups to read, and where, is decided purely (see
        // `plan_group_bitmaps`); here we only perform each planned read. A
        // BLOCK_UNINIT group has `bitmap_block == None`, so `Option::map` skips
        // the read for it; a missing/short bitmap block fails loud via
        // `read_block` rather than silently degrading to an empty stream.
        let descriptors: Vec<(bool, u64)> = br
            .group_descriptors()
            .iter()
            .map(|gd| {
                (
                    gd.flags.contains(GroupDescFlags::BLOCK_UNINIT),
                    gd.block_bitmap,
                )
            })
            .collect();
        let plans = plan_group_bitmaps(
            &descriptors,
            first_data_block,
            blocks_per_group,
            blocks_count,
        );
        let mut owned: Vec<OwnedGroupBitmap> = Vec::with_capacity(plans.len());
        for plan in &plans {
            let bitmap = plan
                .bitmap_block
                .map(|b| br.read_block(b).map_err(map_err))
                .transpose()?;
            owned.push((bitmap, plan.first_block, plan.blocks_in_group));
        }

        let groups: Vec<GroupBitmap<'_>> = owned
            .iter()
            .map(|(bitmap, first_block, blocks_in_group)| GroupBitmap {
                bitmap: bitmap.as_deref(),
                first_block: *first_block,
                blocks_in_group: *blocks_in_group,
            })
            .collect();

        let out: Vec<VfsResult<RunInfo>> = unallocated_runs(&groups, block_size)
            .into_iter()
            .map(|run| {
                Ok(RunInfo {
                    run,
                    alloc: RunAlloc::Unallocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
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
    use super::{
        dirent_kind, free_runs, map_err, node_kind, plan_group_bitmaps, unallocated_runs,
        GroupBitmap,
    };
    use crate::error::Ext4Error;
    use crate::ondisk::{dir_entry::DirEntryType, inode::FileType};
    use forensic_vfs::{ByteRun, NodeKind, RunFlags, VfsError};

    #[test]
    fn free_runs_all_free() {
        assert_eq!(free_runs(&[0x00], 8), vec![(0, 8)]);
    }

    #[test]
    fn free_runs_all_allocated() {
        assert_eq!(free_runs(&[0xFF], 8), Vec::<(u64, u64)>::new());
    }

    #[test]
    fn free_runs_low_nibble_allocated() {
        // 0x0F = 0b0000_1111 -> bits 0..3 set (allocated), bits 4..7 clear (free).
        assert_eq!(free_runs(&[0x0F], 8), vec![(4, 4)]);
    }

    #[test]
    fn free_runs_alternating() {
        // 0xAA = 0b1010_1010 -> free (0) bits at positions 0, 2, 4, 6 (LSB first).
        assert_eq!(free_runs(&[0xAA], 8), vec![(0, 1), (2, 1), (4, 1), (6, 1)]);
    }

    #[test]
    fn free_runs_spans_byte_boundary() {
        assert_eq!(free_runs(&[0x00, 0x00], 12), vec![(0, 12)]);
    }

    #[test]
    fn free_runs_honors_blocks_in_group() {
        // Only the first 3 bits are counted even though the byte has 8 free bits.
        assert_eq!(free_runs(&[0x00], 3), vec![(0, 3)]);
    }

    #[test]
    fn free_runs_zero_blocks() {
        assert_eq!(free_runs(&[0x00], 0), Vec::<(u64, u64)>::new());
    }

    #[test]
    fn free_runs_short_bitmap_treats_missing_as_allocated() {
        // Byte 1 is absent -> bits 8..15 are conservatively allocated, so the free
        // run stops at the end of byte 0 rather than fabricating blocks 8..15.
        assert_eq!(free_runs(&[0x00], 16), vec![(0, 8)]);
    }

    #[test]
    fn unallocated_runs_maps_bits_to_absolute_offsets() {
        let bm_a = [0x0Fu8]; // group A: free bits 4..7
        let bm_c = [0x00u8]; // group C: all free (partial last group)
        let groups = [
            GroupBitmap {
                bitmap: Some(&bm_a),
                first_block: 0,
                blocks_in_group: 8,
            },
            GroupBitmap {
                bitmap: None, // BLOCK_UNINIT: whole group free
                first_block: 8,
                blocks_in_group: 8,
            },
            GroupBitmap {
                bitmap: Some(&bm_c),
                first_block: 16,
                blocks_in_group: 3, // partial last group
            },
        ];
        let run = |off: u64, len: u64| ByteRun {
            image_offset: off,
            len,
            flags: RunFlags::default(),
        };
        assert_eq!(
            unallocated_runs(&groups, 1024),
            vec![
                run(4 * 1024, 4 * 1024),  // group A blocks 4..7
                run(8 * 1024, 8 * 1024),  // uninit group blocks 8..15
                run(16 * 1024, 3 * 1024), // partial group blocks 16..18
            ]
        );
    }

    #[test]
    fn unallocated_runs_uninit_zero_block_group_yields_no_runs() {
        // A None (BLOCK_UNINIT) bitmap bounded to zero data blocks contributes
        // nothing — the empty-group arm of `unallocated_runs`.
        let groups = [GroupBitmap {
            bitmap: None,
            first_block: 0,
            blocks_in_group: 0,
        }];
        assert!(unallocated_runs(&groups, 1024).is_empty());
    }

    #[test]
    fn plan_group_bitmaps_normal_uninit_and_empty() {
        // One pass drives all three per-group outcomes:
        //   group 0 (normal)       -> plans a read of its bitmap block (Some);
        //   group 1 (BLOCK_UNINIT) -> plans no read (None);
        //   group 2 (past the end) -> blocks_in_group == 0, dropped entirely.
        // blocks_per_group = 8, blocks_count = 16, so group 2 starts at block 16.
        let plans = plan_group_bitmaps(&[(false, 7), (true, 99), (false, 5)], 0, 8, 16);
        let got: Vec<_> = plans
            .iter()
            .map(|p| (p.bitmap_block, p.first_block, p.blocks_in_group))
            .collect();
        assert_eq!(got, vec![(Some(7), 0, 8), (None, 8, 8)]);
    }

    #[test]
    fn unallocated_over_minimal_image_yields_runs() {
        use crate::Ext4Fs;
        use forensic_vfs::{FileSystem, RunAlloc};
        use std::io::Cursor;

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        // minimal.img is a committed fixture, so this read is infallible in a
        // checkout; the coverage gate is satisfiable from committed bytes alone.
        let data = std::fs::read(path).expect("committed fixture tests/data/minimal.img");
        let fs = Ext4Fs::open(Cursor::new(data)).unwrap();
        let runs: Vec<_> = fs
            .unallocated()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        // A freshly mkfs'd image always has free space.
        assert!(!runs.is_empty(), "expected unallocated runs on minimal.img");
        for r in &runs {
            assert_eq!(r.alloc, RunAlloc::Unallocated);
            assert!(r.run.len > 0);
        }
    }

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
