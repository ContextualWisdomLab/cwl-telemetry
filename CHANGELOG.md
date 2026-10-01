# Changelog

All notable changes to this unreleased package are recorded here.

## Unreleased

### Fixed

- Prevent reserved security event names from bypassing the durable security
  route and export the same immutable attribute snapshot that admission checked.
- Make trace sampling and span limits explicit, and reject an ambient global SDK
  disable instead of silently returning a no-op runtime.
- Require an exact event-bound JSON Boolean rejection before quarantine and
  count pending plus quarantined rows against the same outbox capacity.
- Reject operational event names longer than 128 characters before export.
- Bound trace and log exports to 16 records and remove inherited baggage and
  TraceState so worst-case admitted batches fit the production Collector's
  65,536-byte ingress limit while preserving trace identity.
- Reject counter increments whose cumulative canonical label-series total would
  exceed the nonnegative signed 64-bit OTLP wire range; repeated handles share
  the same synchronized accounting.
