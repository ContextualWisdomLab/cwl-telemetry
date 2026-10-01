# Changelog

All notable changes to this unreleased package are recorded here.

## Unreleased

### Fixed

- Reject operational event names longer than 128 characters before export.
- Bound trace and log exports to 16 records and remove inherited baggage and
  TraceState so worst-case admitted batches fit the production Collector's
  65,536-byte ingress limit while preserving trace identity.
- Reject counter increments whose cumulative canonical label-series total would
  exceed the nonnegative signed 64-bit OTLP wire range; repeated handles share
  the same synchronized accounting.
