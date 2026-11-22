# Explicit scoped recovery completion (development contract, 2026-11-06)

This phase commits an administrator-approved write release after guarded normal
startup and selected live business checks. It does not certify all Kura
components, hardware, external PID restoration, production profile handoff or
the complete management-system redesign. Every response and receipt retains
`kuraRecoveryVerified=false` and the explicit scope
`administrator-selected-checks`.

The feature is disabled by default. Agent requires a private fixed
`AGENT_RECOVERY_COMPLETION_CONFIG` with schema 1, the exact `healthGrantSha256`,
`releaseOrdinaryWrites=true`, the exact scope above,
`maximumObservationAgeSeconds` (1–600) and `validForSeconds` (60–600). Unknown
fields, a different scope, an implicit approval or a changed health grant fail.
This file is an administrator approval of the selected health policy, not an
automatic claim that those checks cover the entire gateway.

The local administrator methods `recovery.completion.prepare/execute` accept only
`transactionId` and `confirmToken`. Prepare takes the verified health ID/token,
validates all normal/source/sidecar proofs and the same active MainPID, requires
fresh health under both grants, and creates a separate completion ID/token,
nonce, expiry, private source-journal anchor and exact grant archive. Existing
completion plans or retained Java release receipts cannot be overwritten.
Registered Kura-role clients and ordinary local users cannot invoke this route.

Execute repeats the pending checks, persists intent and a create-only release
authorization before one bridge write. The authorization binds the original
normal source, health receipt, policy SHA, source journal, MainPID, nonce and
expiry. It cannot accept commands, unit names, paths or expected configuration
values from the caller. An expired or changed preflight never sends the write.

On Kura, configuration API package 1.7 adds the separate optional
`RecoveryCompletionService`. Both the bootstrap registration and bridge write
capability `kura.recovery.complete` require
`kura.management.recovery.completion.enabled=true`. The verification and
completion switches are distinct, with no agent dependency in ordinary Kura
startup. Without a recovery request the bootstrap remains a no-op.

The Java service accepts one attempt in the admitted normal JVM. It checks the
bounded request and expiry, requires the exact framework target admitted by
the launcher, and runs fresh whole-CM/registration/business health with
the completion nonce, and requires source/managed/property counts and the exact
materialized self-PID list to match the approved observation. All original CM
values remain exact; the existing explicit self-PID rules still apply. No
completion is inferred from a prior read-only success.

Core `ControlledRecovery.commitOrdinaryWriteRelease` authenticates the live
normal admission again and publishes the fixed private create-only
`<normal-receipt>.write-release.properties` before admitting any ordinary writer.
The receipt contains only identities, hashes, counts and the explicit scope.
It contains no passwords, configuration values or caller-selected paths. A
failed publication leaves the core gate closed. Clearing a system property
cannot authorize release. Duplicate attempts cannot overwrite the receipt.

Agent validates the typed reply and exact Java receipt, checks ownership and
permissions, synchronizes the verified file and parent directory independently,
and confirms the bytes and metadata again. A lost reply can be reconciled from
that exact durable receipt; it never sends the release again. The final agent
receipt and state are `COMPLETED_APPROVED_CHECKS`. Ordinary agent writers and
package lifecycle admission recognize this terminal state. Historical backups,
keys, requests and sidecars remain retained.

`writeReleaseCommitted=true` describes the durable authorization/decision.
`agentWritesBlocked=false` describes the agent gate.
`kuraReleaseReplyVerified=true` additionally records a verified successful Java
reply; receipt-only reconciliation does not invent that observation. These flags
do not assert perpetual health or current unit availability.

On reopen, an exact committed Java decision wins over an interrupted final
agent journal marker; missing final agent receipt creation is recoverable
without replay. Pending intent without a valid release receipt or altered
source/archive/receipt evidence stops the three transaction-owned Kura units
and preserves RECOVERY_REQUIRED. Neither a new release nor a Kura restart is
automatically attempted. After committed release, legitimate later CM/snapshot
changes and ordinary shutdown must not be mistaken for drift of an unfinished
recovery; reopening checks immutable completion evidence instead of the mutable
live baseline.

The old recovery launch request remains a one-time retained artifact. A later
ordinary Kura process must use a separate ordinary launch profile without
`kura.recovery.request`. Actual IDEA and systemd validation exercise that
independent path and ordinary writes. Automatic production unit/profile
activation, full component/provider coverage and formal distribution remain
separate deliverables; a prototype request must never become a reusable normal
boot entry point.

An authorized partial-failure forward source can follow independent inverse,
exact file-set, guarded normal and selected live health gates. Completion still
requires its own fixed approval and fresh Java checks; neither a failed forward
request nor a successful inverse alone authorizes release. The completed journal
preserves `source_partial` and null forward `cmApplication`. Its decision remains
limited to administrator-selected-checks and cannot fabricate CM_APPLIED for the
original request. Actual nonempty-original evidence is in console review
`partial-source-completion-20261107.md` (2026-11-07, ff72eb79).

## 2026-11-08: dispatch-journal release publication binding

Core now retains pre-dispatch intents for conditional plans/updates and rollback.
An unresolved intent blocks ordinary snapshot startup before CM seeding. The
normal admitted recovery path can still run with the ordinary write guard.

The completion publisher passes its fixed release-receipt path and exact final
SHA256 to the new ControlledRecovery overload. Before publishing that receipt,
Core forces create-only release links for pending intents, binding their hashes
to the completion/snapshot/decision identities and exact immutable receipt.
A missing receipt leaves the intent unresolved; a changed receipt fails closed.
An exact published receipt can authorize a later ordinary JVM even if the
completion reply was lost, without another release request or an intervening
ordinary write. Old publishers are rejected before publication when an intent
is unresolved. The new bootstrap requires Core's dispatch.release 1.x capability;
Core does not require the optional bootstrap or agent.

These links add no configuration values or passwords, but contain the private
fixed receipt path. Preserve the journal and its bound receipt together.
Consistent backup/restore and path relocation remain separate delivery work.
Do not remove intent/link files to release the gate.

Core233/tool58 tests, fresh-JVM publisher contracts, a three-case real resolver
matrix, new no-agent normal IDEA/GWT startup and six OrbStack JVM file contracts
are documented in console docs/reviews/durable-recovery-contract-20261108.md.
The Orb contract uses a direct owned admission fixture, not the authenticated
agent recovery chain. Actual authorized pending-journal normal/health/completion
and ordinary handoff/business verification remain unproved in that round.
The original selected-checks scope and full-recovery limitations above remain.

## 2026-11-08: explicitly accepting an applied forward source

An UNKNOWN dispatch can leave CM different from the last durable snapshot. An
inverse followed by restoration of that original snapshot set does not by itself
make those two states agree. The administrator may instead explicitly accept a
successfully applied forward recovery candidate as the source for guarded normal
startup. This is a separate, default-off policy; the existing inverse entry keeps
its original meaning.

`AGENT_RECOVERY_FORWARD_NORMAL_CONFIG` names a private administrator-owned JSON
grant. It requires `schema: 1`, `source: "applied-forward"`,
`acceptAppliedForwardSource: true` and `normalStartupAuthoritySha256`. The latter
binds the exact normal startup authority: SHA256 of the newline-joined raw grant
SHA256 and every declared profile-file SHA256, in declared order. Unknown fields,
symlinks, public grant permissions and changed authority fail closed.

The local administrative method `recovery.normal.forward.prepare` accepts only
the applied transaction ID and its confirm token. It requires the original full
CM_APPLIED source receipt and sidecars, an unchanged snapshot inventory including
the selected highest candidate, no inverse and no prior normal plan. Ordinary
Kura-role bridge peers cannot invoke it. The normal execute, health, completion
and independent ordinary handoff retain their existing separate grants and
selected-checks scope. The configured inverse unit must remain stopped; no
inverse request or receipt is synthesized. Once normal dispatch is issued, a
failure is retained and cannot be replayed or branched into an inverse.

The feature's contract checks are distinct from actual native acceptance;
current evidence and any failed native cases are recorded in the console's
authorized-journal-handoff evidence directory. This addition alone does not
prove whole-Kura recovery or formal distribution readiness.

Current Core V1 snapshots carry logical passwords. A validator grant for a plain
V1 artifact must explicitly use `passwordPolicy: "logical-v1"`; its report keeps
logical counts separate and never claims key authentication. The default
`authenticated` policy requires actual outer AES-GCM for V1 passwords. This
policy is independently pinned for forward, normal and ordinary validation;
accepting a forward source never silently changes a validator grant. Set the
health grant's framework level to the exact guarded-normal launcher target.
Ordinary launchers keep their independent no-request configuration.

Guarded normal startup validates logical snapshot passwords against the current
admitted managed CM and preserves their exact stored ciphertext and container
representation. A missing, changed, unauthenticated nonempty or incompatible
value fails before startup CM dispatch; no password equality exception is added
to the whole-managed-CM verifier. This prevents random-IV re-encryption from
changing otherwise identical keystore password fields during normal loading.
Ordinary startup retains its existing independent encryption path.
