#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::Timestamp;
use std::io::{Read, Seek};

/// Type of filesystem event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Created,
    Modified,
    Accessed,
    Changed,
    Deleted,
    Mounted,
}

/// A single event in the forensic timeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: Timestamp,
    pub event_type: EventType,
    pub inode: u64,
    pub path: Option<String>,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
}

/// Generate a forensic timeline from all filesystem timestamps.
pub fn generate_timeline<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<TimelineEvent>> {
    let mut events = Vec::new();

    let sb = reader.block_reader().superblock();
    if sb.mount_time != 0 {
        events.push(TimelineEvent {
            timestamp: Timestamp { seconds: sb.mount_time as i64, nanoseconds: 0 },
            event_type: EventType::Mounted,
            inode: 0,
            path: None,
            size: 0,
            uid: 0,
            gid: 0,
        });
    }

    let all_inodes = reader.iter_all_inodes()?;
    for (ino, inode) in &all_inodes {
        let base = |ts: &Timestamp, event_type: EventType| -> Option<TimelineEvent> {
            if ts.seconds == 0 { return None; }
            Some(TimelineEvent {
                timestamp: *ts,
                event_type,
                inode: *ino,
                path: None,
                size: inode.size,
                uid: inode.uid,
                gid: inode.gid,
            })
        };

        if let Some(e) = base(&inode.crtime, EventType::Created) { events.push(e); }
        if let Some(e) = base(&inode.mtime, EventType::Modified) { events.push(e); }
        if let Some(e) = base(&inode.atime, EventType::Accessed) { events.push(e); }
        if let Some(e) = base(&inode.ctime, EventType::Changed) { events.push(e); }
        if inode.dtime != 0 {
            events.push(TimelineEvent {
                timestamp: Timestamp { seconds: inode.dtime as i64, nanoseconds: 0 },
                event_type: EventType::Deleted,
                inode: *ino,
                path: None,
                size: inode.size,
                uid: inode.uid,
                gid: inode.gid,
            });
        }
    }

    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn generate_timeline_from_minimal() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let events = generate_timeline(&mut reader).unwrap();
        assert!(!events.is_empty());
        for window in events.windows(2) {
            assert!(window[0].timestamp <= window[1].timestamp);
        }
    }

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn forensic_timeline_contains_deletion_events() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let events = generate_timeline(&mut reader).unwrap();
        let deleted: Vec<&TimelineEvent> = events
            .iter()
            .filter(|e| e.event_type == EventType::Deleted)
            .collect();
        assert!(!deleted.is_empty(), "expected at least one Deleted event");
        let deleted_inodes: Vec<u64> = deleted.iter().map(|e| e.inode).collect();
        assert!(deleted_inodes.contains(&21), "expected Deleted event for inode 21");
        assert!(deleted_inodes.contains(&22), "expected Deleted event for inode 22");
    }

    #[test]
    fn forensic_timeline_contains_all_event_types() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let events = generate_timeline(&mut reader).unwrap();
        let has = |et: EventType| events.iter().any(|e| e.event_type == et);
        assert!(has(EventType::Created), "missing Created events");
        assert!(has(EventType::Modified), "missing Modified events");
        assert!(has(EventType::Accessed), "missing Accessed events");
        assert!(has(EventType::Changed), "missing Changed events");
        assert!(has(EventType::Deleted), "missing Deleted events");
    }

    #[test]
    fn forensic_timeline_is_sorted() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let events = generate_timeline(&mut reader).unwrap();
        assert!(events.len() > 1, "need multiple events to verify sorting");
        for window in events.windows(2) {
            assert!(
                window[0].timestamp <= window[1].timestamp,
                "events not sorted: {:?} > {:?}",
                window[0].timestamp,
                window[1].timestamp,
            );
        }
    }
}
