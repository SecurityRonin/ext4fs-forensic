# Cross-Repo Integration Design

## Features

### 1. Ext4Fs::open_ewf(path) one-liner
Optional `ewf` feature on ext4fs. `Ext4Fs::open_ewf("image.E01")` opens EwfReader, passes to Ext4Fs::open(). Feature-gated to keep ewf optional.

### 2. E01 auto-detect in 4n6mount
Extend detect.rs to recognize EWF headers (first 8 bytes). When detected, open via EwfReader, detect filesystem inside, create ForensicFs. Add `ewf` feature to 4n6mount.

### 3. ext4fs MCP server (ext4fs-cli crate)
New workspace member. JSON-RPC stdio MCP following ewf-cli pattern. Tools: ext4fs_open, ext4fs_ls, ext4fs_read, ext4fs_stat, ext4fs_deleted, ext4fs_recover, ext4fs_timeline, ext4fs_search, ext4fs_hash, ext4fs_journal, ext4fs_xattrs, ext4fs_slack. Session management with UUID keys.

### 4. L01 logical evidence in 4n6mount
L01 contains individual files, not disk images. When detected, expose contained files directly under ro/ instead of parsing a filesystem.

### 5. EwfReader in ForensicFs
Ext4ForensicFs<R> is generic — Ext4ForensicFs::new(EwfReader::open(path)?) works. 4n6mount wires: detect E01 → open EwfReader → pass to Ext4ForensicFs.
