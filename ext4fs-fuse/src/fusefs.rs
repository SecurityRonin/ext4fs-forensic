#![forbid(unsafe_code)]

use crate::inode_map::*;
use crate::session::Session;
use ext4fs::ondisk::{DirEntryType, FileType as Ext4FileType, Inode, Timestamp};
use ext4fs::Ext4Fs;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request, TimeOrNow,
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
    session: RefCell<Option<Session>>,
    /// Counter for allocating new overlay inode numbers (for created files).
    overlay_ino_counter: RefCell<u64>,
}

impl Ext4FuseFs {
    pub fn new(fs: Ext4Fs<File>, session: Option<Session>) -> Self {
        Self {
            fs: RefCell::new(fs),
            session: RefCell::new(session),
            overlay_ino_counter: RefCell::new(1),
        }
    }

    /// Check if a session is available (rw/ operations require one).
    fn has_session(&self) -> bool {
        self.session.borrow().is_some()
    }

    /// Get the overlay file ID for a modified ext4 inode.
    fn modified_overlay_id(ext4_ino: u64) -> String {
        format!("ino_{ext4_ino}")
    }

    /// Allocate a new overlay inode number for created files.
    fn alloc_overlay_ino(&self) -> u64 {
        let mut counter = self.overlay_ino_counter.borrow_mut();
        let ino = *counter;
        *counter += 1;
        ino
    }

    /// Get the overlay file ID for a newly created file.
    fn created_overlay_id(counter: u64) -> String {
        format!("new_{counter}")
    }

    /// Build a FileAttr for an overlay-created file.
    fn overlay_created_attr(fuse_ino: u64, size: u64, is_dir: bool) -> FileAttr {
        let kind = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        FileAttr {
            ino: fuse_ino,
            size,
            blocks: size.div_ceil(512),
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind,
            perm: if is_dir { 0o755 } else { 0o644 },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Resolve rw/ parent inode to ext4 parent inode.
    fn rw_parent_to_ext4(&self, parent: u64) -> Option<u64> {
        match parent {
            FUSE_RW_INO => Some(2u64),
            _ => match decode_fuse_ino(parent) {
                InodeNamespace::Rw(ino) => Some(ino),
                _ => None,
            },
        }
    }

    /// Check if an ext4 inode is in the whiteout (deleted) list.
    fn is_whiteout(&self, ext4_ino: u64) -> bool {
        let session = self.session.borrow();
        match session.as_ref() {
            Some(s) => s.overlay.deleted.contains(&ext4_ino),
            None => false,
        }
    }

    /// Find a created overlay entry by parent_ino and name.
    fn find_created_by_name(&self, parent_ino: u64, name: &[u8]) -> Option<(String, u64, bool)> {
        let session = self.session.borrow();
        let session = session.as_ref()?;
        let name_str = std::str::from_utf8(name).ok()?;
        for (id, entry) in &session.overlay.created {
            if entry.parent_ino == parent_ino && entry.name == name_str {
                // Parse the counter from the id ("new_N")
                let counter: u64 = id.strip_prefix("new_").and_then(|s| s.parse().ok())?;
                return Some((id.clone(), counter, false));
            }
        }
        for (id, entry) in &session.overlay.dirs {
            if entry.parent_ino == parent_ino && entry.name == name_str {
                let counter: u64 = id.strip_prefix("new_").and_then(|s| s.parse().ok())?;
                return Some((id.clone(), counter, true));
            }
        }
        None
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
                    let attr = if ino == FUSE_RW_INO && self.has_session() {
                        let mut a = virtual_dir_attr(ino);
                        a.perm = 0o755;
                        a
                    } else {
                        virtual_dir_attr(ino)
                    };
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // rw/ namespace lookup.
        if let Some(ext4_parent) = self.rw_parent_to_ext4(parent) {
            // Check overlay created files first.
            if let Some((id, counter, is_dir)) = self.find_created_by_name(ext4_parent, name_bytes)
            {
                let session = self.session.borrow();
                let session = session.as_ref().unwrap();
                let entry = if is_dir {
                    session.overlay.dirs.get(&id)
                } else {
                    session.overlay.created.get(&id)
                };
                if let Some(entry) = entry {
                    let fuse_ino = rw_ino(counter + 9_000_000);
                    let attr = Self::overlay_created_attr(fuse_ino, entry.size, is_dir);
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }

            // Check if name is a modified file.
            {
                let mut fs = self.fs.borrow_mut();
                match fs.lookup_by_ino(ext4_parent, name_bytes) {
                    Ok(Some(child_ino)) => {
                        // Check whiteout.
                        if self.is_whiteout(child_ino) {
                            reply.error(libc::ENOENT);
                            return;
                        }

                        // Check if modified in overlay.
                        let session = self.session.borrow();
                        let overlay_id = Self::modified_overlay_id(child_ino);
                        if let Some(s) = session.as_ref() {
                            if s.overlay.modified.contains_key(&child_ino) {
                                // Return attrs with overlay file size.
                                match fs.inode(child_ino) {
                                    Ok(inode) => {
                                        let fuse_ino = rw_ino(child_ino);
                                        let mut attr = ext4_to_attr(fuse_ino, &inode);
                                        // Update size from overlay file.
                                        if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                            attr.size = data.len() as u64;
                                            attr.blocks = attr.size.div_ceil(512);
                                        }
                                        reply.entry(&TTL, &attr, 0);
                                        return;
                                    }
                                    Err(_) => {
                                        reply.error(libc::EIO);
                                        return;
                                    }
                                }
                            }
                        }

                        // Not modified, return ext4 attrs under rw/ namespace.
                        match fs.inode(child_ino) {
                            Ok(inode) => {
                                let fuse_ino = rw_ino(child_ino);
                                reply.entry(&TTL, &ext4_to_attr(fuse_ino, &inode), 0);
                            }
                            Err(_) => reply.error(libc::EIO),
                        }
                        return;
                    }
                    Ok(None) => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
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
            let mut attr = virtual_dir_attr(ino);
            if ino == FUSE_RW_INO && self.has_session() {
                attr.perm = 0o755;
            }
            reply.attr(&TTL, &attr);
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
            InodeNamespace::Rw(rw_id) => {
                // Check if this is a created overlay file (counter + 9_000_000).
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if let Some(entry) = s.overlay.created.get(&created_id) {
                            let attr =
                                Self::overlay_created_attr(ino, entry.size, false);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                        if let Some(entry) = s.overlay.dirs.get(&created_id) {
                            let attr =
                                Self::overlay_created_attr(ino, entry.size, true);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                    }
                    reply.error(libc::ENOENT);
                    return;
                }

                // This is an ext4 inode viewed through rw/.
                let ext4_ino = rw_id;
                let mut fs = self.fs.borrow_mut();
                match fs.inode(ext4_ino) {
                    Ok(inode) => {
                        let mut attr = ext4_to_attr(ino, &inode);
                        // If modified, update size from overlay.
                        let session = self.session.borrow();
                        if let Some(s) = session.as_ref() {
                            let overlay_id = Self::modified_overlay_id(ext4_ino);
                            if s.overlay.modified.contains_key(&ext4_ino) {
                                if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                    attr.size = data.len() as u64;
                                    attr.blocks = attr.size.div_ceil(512);
                                }
                            }
                        }
                        reply.attr(&TTL, &attr);
                    }
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

        // rw/ namespace readdir.
        if let Some(ext4_dir_ino) = match ino {
            FUSE_RW_INO => Some(2u64),
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Rw(rw_id) if rw_id < 9_000_000 => Some(rw_id),
                _ => None,
            },
        } {
            let mut fs = self.fs.borrow_mut();
            match fs.read_dir_by_ino(ext4_dir_ino) {
                Ok(entries) => {
                    let session = self.session.borrow();
                    // Build merged entry list: ext4 entries - whiteouts + overlay created.
                    let mut fuse_entries: Vec<(u64, FileType, String)> = Vec::new();

                    for e in &entries {
                        let name = e.name_str();
                        let child_ino = e.inode as u64;

                        // Filter out whiteouts.
                        if let Some(s) = session.as_ref() {
                            if name != "." && name != ".." && s.overlay.deleted.contains(&child_ino)
                            {
                                continue;
                            }
                        }

                        let fuse_ino = if name == "." || name == ".." {
                            if ext4_dir_ino == 2 && name == "." {
                                FUSE_RW_INO
                            } else if ext4_dir_ino == 2 && name == ".." {
                                FUSE_ROOT_INO
                            } else {
                                rw_ino(child_ino)
                            }
                        } else {
                            rw_ino(child_ino)
                        };
                        let kind = dir_entry_type_to_fuse(e.file_type);
                        fuse_entries.push((fuse_ino, kind, name));
                    }

                    // Add overlay created entries for this directory.
                    if let Some(s) = session.as_ref() {
                        for (id, entry) in &s.overlay.created {
                            if entry.parent_ino == ext4_dir_ino {
                                if let Some(counter) =
                                    id.strip_prefix("new_").and_then(|s| s.parse::<u64>().ok())
                                {
                                    let fuse_ino = rw_ino(counter + 9_000_000);
                                    fuse_entries.push((
                                        fuse_ino,
                                        FileType::RegularFile,
                                        entry.name.clone(),
                                    ));
                                }
                            }
                        }
                        for (id, entry) in &s.overlay.dirs {
                            if entry.parent_ino == ext4_dir_ino {
                                if let Some(counter) =
                                    id.strip_prefix("new_").and_then(|s| s.parse::<u64>().ok())
                                {
                                    let fuse_ino = rw_ino(counter + 9_000_000);
                                    fuse_entries.push((
                                        fuse_ino,
                                        FileType::Directory,
                                        entry.name.clone(),
                                    ));
                                }
                            }
                        }
                    }

                    for (i, (entry_ino, kind, name)) in
                        fuse_entries.iter().enumerate().skip(offset)
                    {
                        if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                            break;
                        }
                    }
                    reply.ok();
                }
                Err(_) => reply.error(libc::EIO),
            }
            return;
        }

        // Determine the ext4 inode for this directory.
        let ext4_dir_ino = match ino {
            FUSE_RO_INO => 2u64,
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Ro(ext4_ino) => ext4_ino,
                InodeNamespace::Virtual(_) => {
                    // Other virtual dirs (deleted, etc.) are empty for now.
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
        match decode_fuse_ino(ino) {
            InodeNamespace::Ro(ext4_ino) => {
                let mut fs = self.fs.borrow_mut();
                match fs.read_inode_data_range(ext4_ino, offset as u64, size as usize) {
                    Ok(data) => reply.data(&data),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            InodeNamespace::Rw(rw_id) => {
                // Check if this is a created overlay file.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if s.overlay.created.contains_key(&created_id)
                            || s.overlay.dirs.contains_key(&created_id)
                        {
                            match s.read_overlay_file(&created_id) {
                                Ok(data) => {
                                    let off = offset as usize;
                                    let end = (off + size as usize).min(data.len());
                                    if off >= data.len() {
                                        reply.data(&[]);
                                    } else {
                                        reply.data(&data[off..end]);
                                    }
                                    return;
                                }
                                Err(_) => {
                                    reply.error(libc::EIO);
                                    return;
                                }
                            }
                        }
                    }
                    reply.error(libc::ENOENT);
                    return;
                }

                // ext4 inode under rw/.
                let ext4_ino = rw_id;
                // Check if modified in overlay.
                let session = self.session.borrow();
                if let Some(s) = session.as_ref() {
                    let overlay_id = Self::modified_overlay_id(ext4_ino);
                    if s.overlay.modified.contains_key(&ext4_ino) {
                        match s.read_overlay_file(&overlay_id) {
                            Ok(data) => {
                                let off = offset as usize;
                                let end = (off + size as usize).min(data.len());
                                if off >= data.len() {
                                    reply.data(&[]);
                                } else {
                                    reply.data(&data[off..end]);
                                }
                                return;
                            }
                            Err(_) => {
                                reply.error(libc::EIO);
                                return;
                            }
                        }
                    }
                }
                drop(session);

                // Fall back to ext4.
                let mut fs = self.fs.borrow_mut();
                match fs.read_inode_data_range(ext4_ino, offset as u64, size as usize) {
                    Ok(data) => reply.data(&data),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            _ => {
                reply.error(libc::ENOENT);
            }
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let ext4_ino = match decode_fuse_ino(ino) {
            InodeNamespace::Ro(ext4_ino) => ext4_ino,
            InodeNamespace::Rw(rw_id) if rw_id < 9_000_000 => rw_id,
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

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        match decode_fuse_ino(ino) {
            InodeNamespace::Rw(rw_id) => {
                // Created overlay file.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let mut session = self.session.borrow_mut();
                    let s = session.as_mut().unwrap();

                    let is_known = s.overlay.created.contains_key(&created_id)
                        || s.overlay.dirs.contains_key(&created_id);
                    if !is_known {
                        reply.error(libc::ENOENT);
                        return;
                    }

                    // Read existing overlay data, apply write at offset.
                    let mut buf = s.read_overlay_file(&created_id).unwrap_or_default();
                    let off = offset as usize;
                    let end = off + data.len();
                    if end > buf.len() {
                        buf.resize(end, 0);
                    }
                    buf[off..end].copy_from_slice(data);

                    if let Err(_e) = s.write_overlay_file(&created_id, &buf) {
                        reply.error(libc::EIO);
                        return;
                    }

                    // Update size in metadata.
                    if let Some(entry) = s.overlay.created.get_mut(&created_id) {
                        entry.size = buf.len() as u64;
                    }
                    if let Some(entry) = s.overlay.dirs.get_mut(&created_id) {
                        entry.size = buf.len() as u64;
                    }

                    if let Err(_e) = s.save() {
                        reply.error(libc::EIO);
                        return;
                    }

                    reply.written(data.len() as u32);
                    return;
                }

                // Existing ext4 inode under rw/ — COW on first write.
                let ext4_ino = rw_id;
                let overlay_id = Self::modified_overlay_id(ext4_ino);

                let mut session = self.session.borrow_mut();
                let s = session.as_mut().unwrap();

                // If not yet in overlay, COW: read entire file from ext4.
                if !s.overlay.modified.contains_key(&ext4_ino) {
                    let mut fs = self.fs.borrow_mut();
                    let original = match fs.read_inode_data(ext4_ino) {
                        Ok(d) => d,
                        Err(_) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    };
                    if let Err(_e) = s.write_overlay_file(&overlay_id, &original) {
                        reply.error(libc::EIO);
                        return;
                    }
                    s.overlay
                        .modified
                        .insert(ext4_ino, overlay_id.clone());
                }

                // Read current overlay data, apply write at offset.
                let mut buf = s.read_overlay_file(&overlay_id).unwrap_or_default();
                let off = offset as usize;
                let end = off + data.len();
                if end > buf.len() {
                    buf.resize(end, 0);
                }
                buf[off..end].copy_from_slice(data);

                if let Err(_e) = s.write_overlay_file(&overlay_id, &buf) {
                    reply.error(libc::EIO);
                    return;
                }

                if let Err(_e) = s.save() {
                    reply.error(libc::EIO);
                    return;
                }

                reply.written(data.len() as u32);
            }
            _ => reply.error(libc::EROFS),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let ext4_parent = match self.rw_parent_to_ext4(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_str = match name.to_str() {
            Some(s) => s.to_string(),
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let counter = self.alloc_overlay_ino();
        let created_id = Self::created_overlay_id(counter);
        let fuse_ino = rw_ino(counter + 9_000_000);

        let mut session = self.session.borrow_mut();
        let s = session.as_mut().unwrap();

        // Write empty file to overlay.
        if let Err(_e) = s.write_overlay_file(&created_id, &[]) {
            reply.error(libc::EIO);
            return;
        }

        s.overlay.created.insert(
            created_id,
            crate::session::OverlayEntry {
                parent_ino: ext4_parent,
                name: name_str,
                size: 0,
            },
        );

        if let Err(_e) = s.save() {
            reply.error(libc::EIO);
            return;
        }

        let attr = Self::overlay_created_attr(fuse_ino, 0, false);
        reply.created(&TTL, &attr, 0, 0, 0);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let ext4_parent = match self.rw_parent_to_ext4(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_str = match name.to_str() {
            Some(s) => s.to_string(),
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let counter = self.alloc_overlay_ino();
        let created_id = Self::created_overlay_id(counter);
        let fuse_ino = rw_ino(counter + 9_000_000);

        let mut session = self.session.borrow_mut();
        let s = session.as_mut().unwrap();

        s.overlay.dirs.insert(
            created_id,
            crate::session::OverlayEntry {
                parent_ino: ext4_parent,
                name: name_str,
                size: 0,
            },
        );

        if let Err(_e) = s.save() {
            reply.error(libc::EIO);
            return;
        }

        let attr = Self::overlay_created_attr(fuse_ino, 0, true);
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let ext4_parent = match self.rw_parent_to_ext4(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_bytes = name.as_encoded_bytes();

        // Check if it's a created overlay file first.
        if let Some((id, _counter, _is_dir)) = self.find_created_by_name(ext4_parent, name_bytes) {
            let mut session = self.session.borrow_mut();
            let s = session.as_mut().unwrap();
            s.overlay.created.remove(&id);
            s.overlay.dirs.remove(&id);
            // Remove overlay file on disk too.
            let _ = std::fs::remove_file(s.overlay_file_path(&id));
            if let Err(_e) = s.save() {
                reply.error(libc::EIO);
                return;
            }
            reply.ok();
            return;
        }

        // Look up the ext4 inode and add whiteout.
        let mut fs = self.fs.borrow_mut();
        match fs.lookup_by_ino(ext4_parent, name_bytes) {
            Ok(Some(child_ino)) => {
                let mut session = self.session.borrow_mut();
                let s = session.as_mut().unwrap();
                if !s.overlay.deleted.contains(&child_ino) {
                    s.overlay.deleted.push(child_ino);
                }
                if let Err(_e) = s.save() {
                    reply.error(libc::EIO);
                    return;
                }
                reply.ok();
            }
            Ok(None) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        // rmdir uses the same logic as unlink (whiteout or remove overlay dir).
        self.unlink(_req, parent, name, reply);
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match decode_fuse_ino(ino) {
            InodeNamespace::Rw(rw_id) => {
                if !self.has_session() {
                    reply.error(libc::EROFS);
                    return;
                }

                // Handle truncate (size change).
                if let Some(new_size) = size {
                    // Created overlay file.
                    if rw_id >= 9_000_000 {
                        let counter = rw_id - 9_000_000;
                        let created_id = Self::created_overlay_id(counter);
                        let mut session = self.session.borrow_mut();
                        let s = session.as_mut().unwrap();

                        let mut buf = s.read_overlay_file(&created_id).unwrap_or_default();
                        buf.resize(new_size as usize, 0);
                        if let Err(_e) = s.write_overlay_file(&created_id, &buf) {
                            reply.error(libc::EIO);
                            return;
                        }

                        if let Some(entry) = s.overlay.created.get_mut(&created_id) {
                            entry.size = new_size;
                        }
                        if let Some(entry) = s.overlay.dirs.get_mut(&created_id) {
                            entry.size = new_size;
                        }
                        if let Err(_e) = s.save() {
                            reply.error(libc::EIO);
                            return;
                        }

                        let attr = Self::overlay_created_attr(ino, new_size, false);
                        reply.attr(&TTL, &attr);
                        return;
                    }

                    // Existing ext4 inode — COW then truncate.
                    let ext4_ino = rw_id;
                    let overlay_id = Self::modified_overlay_id(ext4_ino);

                    let mut session = self.session.borrow_mut();
                    let s = session.as_mut().unwrap();

                    if !s.overlay.modified.contains_key(&ext4_ino) {
                        let mut fs = self.fs.borrow_mut();
                        let original = match fs.read_inode_data(ext4_ino) {
                            Ok(d) => d,
                            Err(_) => {
                                reply.error(libc::EIO);
                                return;
                            }
                        };
                        if let Err(_e) = s.write_overlay_file(&overlay_id, &original) {
                            reply.error(libc::EIO);
                            return;
                        }
                        s.overlay.modified.insert(ext4_ino, overlay_id.clone());
                    }

                    let mut buf = s.read_overlay_file(&overlay_id).unwrap_or_default();
                    buf.resize(new_size as usize, 0);
                    if let Err(_e) = s.write_overlay_file(&overlay_id, &buf) {
                        reply.error(libc::EIO);
                        return;
                    }
                    if let Err(_e) = s.save() {
                        reply.error(libc::EIO);
                        return;
                    }

                    // Return updated attrs.
                    let mut fs = self.fs.borrow_mut();
                    match fs.inode(ext4_ino) {
                        Ok(inode) => {
                            let mut attr = ext4_to_attr(ino, &inode);
                            attr.size = new_size;
                            attr.blocks = new_size.div_ceil(512);
                            reply.attr(&TTL, &attr);
                        }
                        Err(_) => reply.error(libc::EIO),
                    }
                    return;
                }

                // No size change — just return current attrs.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if let Some(entry) = s.overlay.created.get(&created_id) {
                            let attr = Self::overlay_created_attr(ino, entry.size, false);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                        if let Some(entry) = s.overlay.dirs.get(&created_id) {
                            let attr = Self::overlay_created_attr(ino, entry.size, true);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                    }
                    reply.error(libc::ENOENT);
                } else {
                    let ext4_ino = rw_id;
                    let mut fs = self.fs.borrow_mut();
                    match fs.inode(ext4_ino) {
                        Ok(inode) => {
                            let mut attr = ext4_to_attr(ino, &inode);
                            let session = self.session.borrow();
                            if let Some(s) = session.as_ref() {
                                let overlay_id = Self::modified_overlay_id(ext4_ino);
                                if s.overlay.modified.contains_key(&ext4_ino) {
                                    if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                        attr.size = data.len() as u64;
                                        attr.blocks = attr.size.div_ceil(512);
                                    }
                                }
                            }
                            reply.attr(&TTL, &attr);
                        }
                        Err(_) => reply.error(libc::EIO),
                    }
                }
            }
            // For non-rw inodes, setattr is not supported.
            _ => reply.error(libc::EROFS),
        }
    }
}
