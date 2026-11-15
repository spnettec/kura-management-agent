# Controlled Kura startup grant (increment 1)

This adapter connects recovery artifact placement to the optional Java bootstrap.
It remains opt-in: `AGENT_RECOVERY_STARTUP_CONFIG` must name a private,
administrator-owned JSON grant, and `AGENT_RECOVERY_VALIDATOR_CONFIG` must also
be configured. No HTTP/UDS request may supply an executable, startup profile,
key path, timeout or receipt path. Existing artifact/unit-only mode is retained
and still reports `kuraRecoveryVerified=false`.

```json
{
  "schema": 1,
  "unit": "explicit-kura.service",
  "requestPath": "/absolute/private/startup/request.properties",
  "receiptDirectory": "/absolute/private/application",
  "timeoutSeconds": 120,
  "profileFiles": [
    {"path": "/absolute/fixed/jvm.restore.args", "sha256": "<64 lowercase hex digits>"}
  ]
}
```

The example inventory is abbreviated. An actual grant must pin the fixed unit
file/launcher, JVM arguments/configuration and bootstrap/core/runtime dependencies
that establish the intended launch profile. The fixed JVM profile points at
`-Dkura.recovery.request=<requestPath>`, launches the bootstrap at framework level
1, and lets the normal launcher advance to 5. Agent does not dynamically rewrite
unit definitions or run user commands. Administrators control all ancestor paths,
unit definitions and dynamic unit overrides as well as these files. Profile pins
prove specified file content; they are not attestation of systemd's whole effective
configuration. Formal installation/upgrade generation of this grant is pending.

Unknown/duplicate JSON fields and ambiguous inputs are rejected. The grant is at
most 256 KiB, with 1–512 distinct files, each at most 256 MiB and at most 2 GiB in
total. Larger limits than snapshot files are necessary for actual Kura Web2/script
bundles. Each file and its immediate parent must be regular/non-symlink and not
group/other writable; file owner is root or the agent user. The grant itself is
private. Request/receipt parent directories must be private and owned by the
snapshot/Kura UID. Every hash is rechecked at prepare, execute, publication and
receipt acceptance. Keys/mode/password policy come exclusively from the exact
Java validator grant fingerprint retained in the private journal.

Prepare binds a new restore ID, exact candidate hash/target, profile fingerprint,
request hash and unique application receipt path. Existing requests or receipt,
CM backup and bundle-level sidecars block a new prepare. Nothing is overwritten
or automatically replayed. Execute validates before/after stopping, durably backs
up snapshots and publishes the candidate. It persists `controlled_issued=true`
before publishing the create-only startup request. It then starts only the
allowlisted unit and waits for Java's application receipt.

Acceptance requires exact schema/status/restore ID/snapshot hash, explicit
`fullRecoveryVerified=false`/`businessHealth=UNVERIFIED`, bounded complete PID
action lists, encrypted backup hash and retained bundle-level ledger. Agent
checks request/candidate/profile stability and the real unit state again. It
stores hashes of all application evidence and enters **AWAITING_COMPLETION**.
It does not write a terminal success receipt, remove the upload, clear the
request or release the shared write barrier. `recovery.status` exposes
`awaitsExplicitCompletion` and the CM application proof; overall verification
remains `controlled-cm-application-only` and `kuraRecoveryVerified=false`.

A restarted agent rechecks pending evidence without starting/replaying Kura. A
missing/changed receipt, backup, ledger, candidate, validator grant or unit state
stops the allowlisted Kura unit and enters RECOVERY_REQUIRED. Any crash after
startup intent, or failed execute/rollback after that intent, follows the same
rule. Snapshot-only compensation cannot undo CM changes, so it cannot settle
this transaction. All requests, sidecars, staging and candidate remain retained.
Do not remove a request, clear a journal or start normally as a completion shortcut.

Pending: agent transaction integration of CM API-level compensation, explicit business/bridge health contract and
completion that releases writes, current external network/firewall authority,
full component applicability, key grant for independent service UIDs, and formal
packaging. CM_APPLIED or an active JVM is not complete gateway recovery.

Recovery prepare/execute/rollback have a separate 600-second UDS response budget,
covering bounded validation, unit actions and application evidence. A response
timeout is OUTCOME_UNKNOWN: query the existing transaction; do not resend. The
blocking transaction can continue after a disconnected/timed-out caller. Other
local RPC budgets are unchanged. The full runtime test exposed and corrected the
previous generic 25-second recovery timeout.

The new Java bootstrap can also retain compensation evidence. When a CM_APPLIED
receipt has `applied.sha256`, agent requires matching `.cm-applied.aes`, verifies
the five-field pre-mutation `.cm-plan.properties` identity/backup/intent anchor,
and verifies `.cm-intended.aes`. Their exact fingerprints become part of pending
application evidence and are rechecked after agent restart. Missing/changed
sidecars enter RECOVERY_REQUIRED without overwriting them. Historical receipts
without this field remain readable with no compensation evidence; they do not
gain compensation authorization. This evidence reader does not yet invoke Java's
experimental inverse branch, acknowledge business health or release writes.
Native IDEA and Orb full-Kura selected DS forward/inverse recovery and original
GWT login now pass; each exact audit restored 26 configurations/187 properties
including ciphertext. Orb wrong-source rejection precedes mutation/activation.
Reopening agent with pending Kura stopped preserves the exact new compensation
proof, enters RECOVERY_REQUIRED and blocks upload without replay. The positive
agent restart while Kura stays active was not retested for this increment.
Inverse validation used an explicit new Java bootstrap request, not agent rollback.
All new fixture processes are stopped; original Orb services remain on packages
console26/agent20. Full recovery, explicit completion and release remain pending.


Subsequent opt-in local agent inverse preparation/execution is implemented and
validated in `cm-compensation-v1.md` and the console review
`agent-cm-inverse-20261105.md`. Historical descriptions above retain their
increment scope. Full snapshot-set compensation, partial-source authorization,
health/completion and release remain pending.
