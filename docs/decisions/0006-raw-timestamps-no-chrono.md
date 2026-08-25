# 6. Forensic timestamps as raw `(i64 seconds, u32 nanoseconds)`; no `chrono`, no timezone normalization

Date: 2026-07-24
Status: Accepted

## Context

ext4 stores up to five timestamps per inode (atime, mtime, ctime, crtime, and
dtime on deletion), with nanosecond precision and a 34-bit epoch extension via
the two low bits of the "extra" word (so dates run past 2038 toward ~2446). A
forensic timeline must preserve these values *exactly* as recorded, without
imposing a timezone or a calendar library's interpretation — the examiner, not
the parser, decides how to render an instant, and any lossy conversion or
timezone assumption is a defensibility risk in a report.

## Decision

Represent every timestamp as a plain `Timestamp { seconds: i64, nanoseconds:
u32 }` value (`core/src/ondisk/inode.rs`), decoded by `decode_timestamp`
which sign-extends the 32-bit field when no extra word is present and applies the
epoch-extension bits when it is. Order timestamps by `(seconds, nanoseconds)` via
a hand-written `Ord` (no floating point). Take **no `chrono` / `time`
dependency**; emit no timezone-localized strings from the core.

## Consequences

- Timestamps round-trip losslessly and carry no hidden timezone assumption —
  suited to court-facing timelines where the raw value is the evidence.
- The core stays dependency-light (one fewer transitive tree) and avoids the MSRV
  and audit surface a datetime crate would add.
- Rendering to a human-readable local time is a *consumer* concern (CLI, MCP
  output, a downstream orchestrator), deliberately kept out of the parser.
- The `i64` seconds field spans the full extended ext4 range, so no valid on-disk
  timestamp overflows the in-memory representation.
