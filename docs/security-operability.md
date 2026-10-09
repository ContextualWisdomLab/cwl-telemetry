# Security and Operability Runbook

Status: Proposed. This runbook defines the intended control surface; it is not
evidence of a production deployment.

## Threat model and trust boundaries

Untrusted inputs include every OTLP record and attribute, HTTP header/body,
environment-supplied destination, persisted row, SIEM response, review comment,
and dependency artifact. Trusted configuration is limited to operator-mounted
TLS material, scoped bearer-token files, tenant identity, approved CA roots,
and immutable release artifacts after their digests are verified.

The principal risks are cross-tenant admission, credential disclosure,
operational/security route confusion, replay or conflicting identity, loss of
pending evidence, false delivery, unbounded resource consumption, and
supply-chain substitution.

## Deployment preflight

Before enabling any traffic:

1. Verify the package version and digest against the immutable release. Never
   install from a branch URL.
2. Verify the Collector image digest used by the tested release and validate
   `collector/production.yaml` before starting it.
3. Mount receiver certificate, private key, ingress token, backend token,
   security-consumer token, and CA roots as private regular files. Do not place
   their values in arguments, source, logs, or telemetry.
4. Provide a durable writable Collector queue volume and a private durable
   outbox path. Backups and restores must preserve file ownership and mode.
5. Bind one receiver credential to one tenant reference. Use distinct
   credentials and outboxes across tenants.
6. Allow only approved HTTPS backend and security-consumer origins at the
   network boundary. A URL variable is not authorization.
7. Start the receiver on a private interface unless an authenticated ingress
   proxy is the explicitly tested boundary.
8. Run the release's contract and recovery canaries against staging. Record
   exact image/package digests and redacted results.

Startup must fail closed when a credential is malformed, a tenant identifier is
invalid, the outbox is not a private regular file, TLS configuration cannot be
loaded, or the destination contract is not approved.

## Health and service-level evidence

Monitor process liveness separately from delivery readiness. Readiness requires
the receiver to accept an authenticated schema-v1 canary, commit it, and expose
it to a sender test without losing or falsely delivering the row.

The open performance acceptance target is receiver p95 at or below 20 ms on
declared hardware for 100 requests/second, concurrency 16, a realistic
1 KiB/64 KiB mix, and a 100,000-row backlog. Report all rejections and
timeouts. Measure sender overhead against a loopback acknowledgement gateway
separately from external SIEM latency. Do not shrink samples or omit failures.

Alert on sustained Collector queue growth, receiver 408/413/503 responses,
outbox capacity, pending age, any quarantine row, repeated sender failure,
certificate/token expiry, persistent-volume errors, and restart loops. Do not
emit record bodies or credentials in alerts.

## Sender operation

Run at most one sender per outbox. Supply the scoped gateway token through
standard input and use an approved CA file when private trust is required. A
zero exit means the bounded batch completed without quarantine. Exit status 2
means at least one exact event-specific rejection was quarantined and requires
operator review. Other failure leaves unacknowledged rows pending.

Quarantine is neither delivery nor deletion. Record the event ID, tenant,
gateway revision, response classification, exact sender revision, and operator
decision in the incident system without copying sensitive record content.

## Backup, restore, and recovery rehearsal

Back up the outbox and Collector persistent queue using an operator-approved
encrypted mechanism. Never copy a live SQLite file without a consistent backup
operation. At least once before production and after storage changes:

1. stop or quiesce the relevant writer;
2. take and integrity-check the backup;
3. restore to an isolated environment with original private modes;
4. start the exact release revision;
5. prove pending rows remain pending, acknowledged rows are not resent, and
   quarantined rows remain visible;
6. exercise a lost acknowledgement and restart, verifying safe idempotent
   replay;
7. record timestamps, revisions, counts, duration, and redacted failure output.

A failed rehearsal blocks production readiness. Preserve the original evidence
until the failure is understood; never mark rows delivered to make a rehearsal
pass.

## Incident response

1. Contain: disable the affected tenant route or sender while preserving the
   outbox and Collector queue.
2. Preserve: snapshot metadata, exact revisions, configuration hashes, row
   counts by state, timestamps, and redacted logs. Do not export raw records to
   a ticket.
3. Rotate: revoke affected tokens/certificates through their owning system.
4. Diagnose: distinguish admission failure, persistence failure, route mixing,
   gateway rejection, ambiguous acknowledgement, capacity, and infrastructure
   startup failure.
5. Recover: restore or replay only through the released interfaces and
   idempotency contract.
6. Verify: rerun contract, recovery, security, and performance evidence on the
   repaired exact revision.
7. Review: update the Gap baseline, threat controls, and runbook; do not claim
   closure until independent review and immutable release evidence exist.

## Retention and deletion

The code currently expires acknowledged replay rows after seven days. The
Proposed governance baseline describes 90-day operational and 365-day
normalized-security limits, but applicable legal, contractual, tenant, and
deployment controls remain unverified. Pending and quarantined evidence must
not be deleted merely to regain capacity. A production retention policy needs
an approved owner, legal basis, hold behavior, tested expiry job, audit trail,
and restore-compatible deletion procedure.
