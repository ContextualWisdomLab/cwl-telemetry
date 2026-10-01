# Changelog

All notable changes to this unreleased package are recorded here.

## Unreleased

### Fixed

- Reject operational event names longer than 128 characters before export.
- Bound trace and log exports to 16 records so worst-case admitted batches fit
  the production Collector's 65,536-byte ingress limit.
- Reject counter increments whose cumulative instrument total would exceed the
  nonnegative signed 64-bit OTLP wire range.
