# Changelog

All notable changes to `ext4fs-core` (the reader, imported as `ext4fs`) are
documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6](https://github.com/SecurityRonin/ext4fs-forensic/compare/v0.2.5...v0.2.6) - 2026-07-22

### Added

- *(ext4fs-core)* GREEN — enumerate unallocated extents from block bitmaps

### Fixed

- *(ext4fs-core)* panic-free reader + enforce unwrap/expect deny

## [0.2.4](https://github.com/SecurityRonin/ext4fs-forensic/compare/v0.2.3...v0.2.4) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5

## [0.2.3]

- Current published reader: pure-Rust, `forbid(unsafe)`, panic-free-by-lint,
  input-fuzzed ext2/3/4 parser — superblock, inodes, extents, and directory
  navigation, with forensic recovery helpers.

<!-- release-plz appends new versions above this line, newest first. -->
