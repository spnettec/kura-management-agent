# Explicit CM inverse transaction (development contract, 2026-11-05)

This increment adds an opt-in local administrator transaction around the Java
inverse startup branch. It is not full gateway recovery or snapshot-file-set
completion. Ordinary configuration writes stay blocked throughout.

`AGENT_RECOVERY_COMPENSATION_STARTUP_CONFIG` grants an independent fixed startup
profile using the same schema as `AGENT_RECOVERY_STARTUP_CONFIG`. Both profiles
are required. The inverse profile must name a different allowlisted unit and a
different request path. Administrators must pin the launcher, runtime, arguments,
unit configuration and shared framework storage in the profile inventory. No
caller can supply a command, unit, request path, source receipt or arbitrary key.
The environment variable is absent by default. Formal package/UID grants remain
pending.

Only local administrator UDS requests may call:

- `recovery.compensation.prepare` with the original `transactionId` and original
  `confirmToken`. The source must be AWAITING_COMPLETION or RECOVERY_REQUIRED,
  have an exact CM_APPLIED application proof including compensation sidecars,
  and have no previous inverse. The current snapshot set must equal the original
  baseline plus the admitted candidate. An unchanged validator/key grant,
  original request/receipt/ledger/backup/intent/applied evidence and both fixed
  startup grants are required. Historical receipts lacking compensation evidence
  cannot gain authorization. Partial Java failures without a proven CM_APPLIED
  source remain for explicit inspection; this contract does not infer them.
- Preparation returns a **new** inverse transaction ID, confirmation token,
  target digest and fixed inverse unit. It retains a create-only source journal
  anchor and records COMPENSATION_PREPARED. It does not stop either unit, publish
  a request or mutate CM. Normal uploads and configuration writes stay blocked.
- `recovery.compensation.execute` requires that new ID/token. It rechecks all
  source and snapshot evidence, stops the original unit, verifies the inverse
  unit is stopped, then persists inverse intent before publishing a new highest
  AES snapshot containing the exact original CM backup bytes and a create-only
  inverse request. The original request/candidate/evidence are never replaced.
  The request binds original receipt/plan hashes, uses the original key grant
  and authenticated-password policy, and forces AES-GCM artifact mode.

Only a matching Java CM_APPLIED inverse receipt with exact compensation evidence
and exclusive unit state reaches AWAITING_COMPENSATION_COMPLETION. It explicitly
keeps `kuraRecoveryVerified=false`; no final success or write release is produced.
Source snapshots, forward and inverse backups, requests, receipts and staging are
retained. Full snapshot-file compensation, ordinary boot consistency, bridge and
business-health acceptance, empty-original admission and explicit completion
remain pending. Do not remove requests or edit the journal to simulate completion.

Execute is single-attempt. Inverse intent persisted before publication or any
interruption is never automatically resent. On agent reopen an intact applied
inverse can remain pending without unit restart. Any other inverse state or
changed proof stops both fixed units and enters RECOVERY_REQUIRED, retaining
all evidence. A stop failure is reported for operator action. Existing
`recovery.rollback` keeps its conservative stop/retain behavior for controlled
transactions, and stops both units if an inverse exists; it does not bypass this
separate authorization workflow.

Both new RPCs use the existing 600-second recovery response budget. A disconnected
caller or OUTCOME_UNKNOWN must query `recovery.status` without repeating execute.
Status exposes inverse identity, target, issued flag and application proof but
never confirmation tokens. These endpoints are not exposed as ordinary remote
center operations in this increment.

Validation status and exact native/Linux boundaries are recorded in
`kura-management-console/docs/reviews/agent-cm-inverse-20261105.md` when the
increment's ordered verification completes. Unit fixtures use simulated systemd
and Java receipts; they alone do not prove Kura business recovery.


The subsequent retained snapshot-file-set phase is implemented and verified in
`snapshot-set-compensation-v1.md` and the console review
`snapshot-set-compensation-20261106.md`. This supersedes only the file-set
compensation gap above. Normal boot, partial CM-source admission, health and
explicit completion/write release remain pending.

## Authenticated empty original set (2026-11-07, d1994c05)

The current Java bootstrap now accepts the exact authenticated original CM
backup when that retained backup contains zero managed records. This supersedes
only the empty-original inverse admission gap above. The agent's source receipt,
plan, backup/intent/applied hashes, fixed unit/profile, independent inverse
identity, single-attempt execution and pending-state rules remain unchanged.
No Rust production source or general upload authorization was relaxed.

The inverse still reaches AWAITING_COMPENSATION_COMPLETION with ordinary writes
blocked. Normal startup, business health, completion/write-release policy for an
empty or partial original CM set, and admission from a partially failed source
remain separate pending work. Scope-specific native and real VM evidence is in
`kura-management-console/docs/reviews/empty-original-cm-inverse-20261107.md`.

## Explicit partial-failure source grant (2026-11-07, b9eb0ad3)

The independent inverse startup profile may now explicitly set
`"allowPartialSource": true`. It defaults to false when absent. This supersedes
the partial-source admission gap above; it does not authorize ordinary startup,
health acceptance, completion or write release for that source.

Without a forward `CM_APPLIED` proof, preparation requires a durably issued
controlled request, `RECOVERY_REQUIRED`, a stopped source unit, the unchanged
candidate and original startup/validator/key grants, and exact private Java
failure evidence. The failure receipt must have exactly the schema, restore ID,
`RECOVERY_REQUIRED`, `fullRecoveryVerified=false` and blocked-health fields.
The complete plan must bind the original snapshot, encrypted backup and encrypted
intent hashes; the original bundle ledger must also be intact. Missing, changed,
unsafe or ambiguous evidence cannot authorize an inverse.

The journal stores `source_partial` separately from `source_application`, with
exactly one source grade. No forward applied digest, action count or application
success is inferred. Existing applied-source journals retain their serialized
shape. Prepare and status report `sourceStatus=RECOVERY_REQUIRED` for this path;
the forward `cmApplication` remains null even after a successful inverse.

Execution rechecks the opt-in and all original evidence before publishing the
new inverse. Reopen only observes an intact already-applied inverse; it never
reissues the failed forward request. The inverse still stops at
`AWAITING_COMPENSATION_COMPLETION`, blocks ordinary writers and preserves both
transactions and all encrypted sidecars. This grant is local administrator
policy, not a caller-supplied RPC option or an ordinary registration permission.

Ordered verification and the controlled CM-fault boundary are recorded in
`kura-management-console/docs/reviews/partial-cm-source-compensation-20261107.md`.

The subsequent ff72eb79 verification follows a new partial-failure transaction
with a nonempty original backup through exact snapshot retention, guarded normal,
actual whole-CM/selected business health, independently approved completion and
separate ordinary startup. See console review `partial-source-completion-20261107.md`.
Every phase retains its own default-off grant; the original source stays partial
and cmApplication null. This supersedes only that tested continuation gap, not
empty-original policy, all production applicability, automatic boot handoff or
formal distribution.
