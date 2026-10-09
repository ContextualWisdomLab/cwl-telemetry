# CLAUDE.md

Read and follow `AGENTS.md` before changing this repository.

The authoritative continuation order is:

1. `docs/product-technical-gap-baseline.md` for PRD/TRD, exact evidence, and
   open commercialization Gaps;
2. `ARCHITECTURE.md` for bounded contexts, ports, owned data, and invariants;
3. `docs/security-operability.md` for deployment, recovery, and incident
   procedures;
4. the current PR head, review threads, and workflow jobs for live state.

Do not treat this pre-release branch as a dependency. Do not force-push, copy
the source into consumers, read the private outbox cross-service, or claim a
release/deployment from local tests. Behavioral work begins with a failing
test; documentation-only work must still reconcile the live baseline and
CHANGELOG.
