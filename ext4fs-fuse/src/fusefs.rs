#![forbid(unsafe_code)]

use crate::inode_map::*;
use ext4fs::ondisk::{DirEntryType, FileType as Ext4FileType, Inode, Timestamp};
use ext4fs::Ext4Fs;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::File;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

/// Virtual directory names at the FUSE root.
const VIRTUAL_DIRS: &[(u64, &str)] = &[
    (FUSE_RO_INO, "ro"),
    (FUSE_RW_INO, "rw"),
    (FUSE_DELETED_INO, "deleted"),
    (FUSE_JOURNAL_INO, "journal"),
    (FUSE_METADATA_INO, "metadata"),
    (FUSE_UNALLOCATED_INO, "unallocated"),
    (FUSE_SESSION_INO, "session"),
];

pub struct Ext4FuseFs {
    fs: RefCell<Ext4Fs<File>>,
}

impl Ext4FuseFs {
    pub fn new(fs: Ext4Fs<File>) -> Self {
        Self {
            fs: RefCell::new(fs),
        }
    }
}

/// Convert an ext4 `Timestamp` to `SystemTime`.
fn ts_to_systime(t: &Timestamp) -> SystemTime {
    if t.seconds >= 0 {
        UNIX_EPOCH + Duration::new(t.seconds as u64, t.nanoseconds)
    } else {
        UNIX_EPOCH
    }
}

/// Build a `FileAttr` from an ext4 `Inode`.
fn ext4_to_attr(fuse_ino: u64, inode: &Inode) -> FileAttr {
    let kind = match inode.file_type() {
        Ext4FileType::RegularFile => FileType::RegularFile,
        Ext4FileType::Directory => FileType::Directory,
        Ext4FileType::Symlink => FileType::Symlink,
        Ext4FileType::CharDevice => FileType::CharDevice,
        Ext4FileType::BlockDevice => FileType::BlockDevice,
        Ext4FileType::Fifo => FileType::NamedPipe,
        Ext4FileType::Socket => FileType::Socket,
        Ext4FileType::Unknown => FileType::RegularFile,
    };

    FileAttr {
        ino: fuse_ino,
        size: inode.size,
        blocks: inode.size.div_ceil(512),
        atime: ts_to_systime(&inode.atime),
        mtime: ts_to_systime(&inode.mtime),
        ctime: ts_to_systime(&inode.ctime),
        crtime: ts_to_systime(&inode.crtime),
        kind,
        perm: inode.mode & 0o7777,
        nlink: inode.links_count as u32,
        uid: inode.uid,
        gid: inode.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Build a synthetic `FileAttr` for a virtual directory.
fn virtual_dir_attr(ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o555,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Convert a `DirEntryType` to a fuser `FileType`.
fn dir_entry_type_to_fuse(t: DirEntryType) -> FileType {
    match t {
        DirEntryType::RegularFile => FileType::RegularFile,
        DirEntryType::Directory => FileType::Directory,
        DirEntryType::Symlink => FileType::Symlink,
        DirEntryType::CharDevice => FileType::CharDevice,
        DirEntryType::BlockDevice => FileType::BlockDevice,
        DirEntryType::Fifo => FileType::NamedPipe,
        DirEntryType::Socket => FileType::Socket,
        DirEntryType::Unknown => FileType::RegularFile,
    }
}

impl Filesystem for Ext4FuseFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_bytes = name.as_encoded_bytes();

        // Virtual root: resolve virtual directory names.
        if parent == FUSE_ROOT_INO {
            for &(ino, dir_name) in VIRTUAL_DIRS {
                if name_bytes == dir_name.as_bytes() {
                    reply.entry(&TTL, &virtual_dir_attr(ino), 0);
                    return;
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // ro/ namespace: the ro/ virtual dir itself maps to ext4 root (inode 2).
        let ext4_parent = match parent {
            FUSE_RO_INO => 2u64,
            _ => match decode_fuse_ino(parent) {
                InodeNamespace::Ro(ino) => ino,
                _ => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
        };

        let mut fs = self.fs.borrow_mut();
        match fs.lookup_by_ino(ext4_parent, name_bytes) {
            Ok(Some(child_ino)) => match fs.inode(child_ino) {
                Ok(inode) => {
                    let fuse_ino = ro_ino(child_ino);
                    reply.entry(&TTL, &ext4_to_attr(fuse_ino, &inode), 0);
                }
                Err(_) => reply.error(libc::EIO),
            },
            Ok(None) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // Virtual root.
        if ino == FUSE_ROOT_INO {
            reply.attr(&TTL, &virtual_dir_attr(FUSE_ROOT_INO));
            return;
        }

        // Virtual top-level directories.
        if (FUSE_RO_INO..=FUSE_SESSION_INO).contains(&ino) {
            // For FUSE_RO_INO, we could return the ext4 root attrs, but
            // treating it as a virtual dir is simpler and consistent.
            reply.attr(&TTL, &virtual_dir_attr(ino));
            return;
        }

        match decode_fuse_ino(ino) {
            InodeNamespace::Ro(ext4_ino) => {
                let mut fs = self.fs.borrow_mut();
                match fs.inode(ext4_ino) {
                    Ok(inode) => reply.attr(&TTL, &ext4_to_attr(ino, &inode)),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let offset = offset as usize;

        // Virtual root directory.
        if ino == FUSE_ROOT_INO {
            let entries: Vec<(u64, FileType, &str)> = vec![
                (FUSE_ROOT_INO, FileType::Directory, "."),
                (FUSE_ROOT_INO, FileType::Directory, ".."),
                (FUSE_RO_INO, FileType::Directory, "ro"),
                (FUSE_RW_INO, FileType::Directory, "rw"),
                (FUSE_DELETED_INO, FileType::Directory, "deleted"),
                (FUSE_JOURNAL_INO, FileType::Directory, "journal"),
                (FUSE_METADATA_INO, FileType::Directory, "metadata"),
                (FUSE_UNALLOCATED_INO, FileType::Directory, "unallocated"),
                (FUSE_SESSION_INO, FileType::Directory, "session"),
            ];
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // Determine the ext4 inode for this directory.
        let ext4_dir_ino = match ino {
            FUSE_RO_INO => 2u64,
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Ro(ext4_ino) => ext4_ino,
                InodeNamespace::Virtual(_) => {
                    // Other virtual dirs (rw, deleted, etc.) are empty for now.
                    if offset == 0 {
                        let _ = reply.add(ino, 1, FileType::Directory, ".");
                        let _ = reply.add(FUSE_ROOT_INO, 2, FileType::Directory, "..");
                    }
                    reply.ok();
                    return;
                }
                _ => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_dir_by_ino(ext4_dir_ino) {
            Ok(entries) => {
                // Build the full entry list: remap . and .. for the ro/ root,
                // and translate all inode numbers.
                let fuse_entries: Vec<(u64, FileType, String)> = entries
                    .iter()
                    .map(|e| {
                        let name = e.name_str();
                        let fuse_ino = if name == "." || name == ".." {
                            if ext4_dir_ino == 2 && name == "." {
                                FUSE_RO_INO
                            } else if ext4_dir_ino == 2 && name == ".." {
                                FUSE_ROOT_INO
                            } else {
                                ro_ino(e.inode as u64)
                            }
                        } else {
                            ro_ino(e.inode as u64)
                        };
                        let kind = dir_entry_type_to_fuse(e.file_type);
                        (fuse_ino, kind, name)
                    })
                    .collect();

                for (i, (entry_ino, kind, name)) in fuse_entries.iter().enumerate().skip(offset) {
                    if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let ext4_ino = match decode_fuse_ino(ino) {
            InodeNamespace::Ro(ext4_ino) => ext4_ino,
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_inode_data_range(ext4_ino, offset as u64, size as usize) {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let ext4_ino = match decode_fuse_ino(ino) {
            InodeNamespace::Ro(ext4_ino) => ext4_ino,
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_link_by_ino(ext4_ino) {
            Ok(target) => reply.data(&target),
            Err(_) => reply.error(libc::EIO),
        }
    }
}
