# Guarded ordinary Kura startup (development contract, 2026-11-06)

This nonterminal phase follows exact CM inverse and snapshot-file-set compensation.
It exercises Kura's ordinary snapshot/CM startup while retaining the recovery write
gate. It does not release ordinary writes, certify business health, or complete
recovery. The optional bootstrap remains a no-op when no request is present;
Kura still starts independently without agent.

Local administrator UDS methods `recovery.normal.prepare/execute` accept only a
transaction ID and confirmation token. They use the recovery response budget of
600 seconds. The prepare input is the applied snapshot-set ID/token; execute
requires its own new `rec-...` ID/token. A caller cannot supply a command, unit,
path, crypto key or permissive format policy. UNKNOWN/OUTCOME_UNKNOWN means query
the existing transaction, never resend execution.

An independent fixed `AGENT_RECOVERY_NORMAL_STARTUP_CONFIG` is required. Its unit
and request path must differ from both original and inverse profiles, and its
unit must be explicitly allowlisted. The default is disabled. A normal baseline
may have a different historical password representation from an uploaded
candidate. `AGENT_RECOVERY_NORMAL_VALIDATOR_CONFIG` optionally grants that exact
baseline format/key policy independently. Without it the original validator
remains mandatory; there is no automatic downgrade. Changing the upload grant to
read a legacy baseline is not permitted by this phase. The baseline grant and
all tool/key inputs are fingerprinted again before execution and on reopen.

Prepare requires AWAITING_SNAPSHOT_COMPLETION, no earlier normal plan, both old
units stopped, the complete original active inventory and metadata, retained
candidates, original backup/manifest, snapshot-set receipt, the original source
checkpoint, all inverse application sidecars and journal anchors. It validates the highest original
canonical `snapshot_<number>.xml`. Empty original sets and ambiguous filenames
are refused. It creates a source-journal anchor and new plan without starting a
unit or modifying active snapshots. There is no terminal shortcut for old CM
receipts without exact inverse evidence.

Execute rechecks every proof and the stopped third unit, persists intent before
publishing a create-only request, then starts only the fixed third unit. Java
holds SCR/business bundles, authenticates the original snapshot, inverse
CM_APPLIED receipt and exact encrypted `.cm-applied.aes`, and compares current CM
through its public API including ciphertext representation. The bootstrap does
not apply or compensate CM in `normal-read-only` mode. It saves a private
encrypted observation and bundle-level ledger, admits ordinary loading and
publishes `NORMAL_BOOT_ADMITTED` before restoring launch levels. Ordinary startup
may perform its usual CM seeding/merging; ordinary management mutation APIs
remain blocked throughout.

The core admission returns no replacement configuration list, so Kura runs its
original loader rather than replaying the inverse candidate. Enumeration must
use the admitted directory; canonical highest-artifact identity and SHA remain
pinned. In this guarded mode only, empty-file deletion, `.bad` renaming, automatic
snapshot encryption and decode fallback are refused. Ordinary non-recovery Kura
retains its existing behavior. Clearing the request property cannot release the
in-process gate.

Agent accepts only the distinct receipt with matching request/profile/source
identity, encrypted observation and ledger hashes, unchanged original inventory,
both prior units stopped and the third unit active. It records
AWAITING_NORMAL_BOOT_COMPLETION with `normalBootVerified=false`,
`businessHealth=UNVERIFIED`, `kuraRecoveryVerified=false` and
`awaitsExplicitCompletion=true`. Reopen repeats proof checks without starting or
resending anything. Interruption, evidence drift or loss of the active unit stops
all three fixed units and retains RECOVERY_REQUIRED. Upload and ordinary writers
remain blocked. Intentional validation shutdown is recorded separately from the
last journal state; it is not claimed to pass a later active-unit reopen.

Unit contracts cover independent grants/tokens, continued blocking, no duplicate
execution, source/active/profile drift before start, interrupted intent, wrong
source receipts, changed observations on reopen and independent baseline-policy
fingerprints. Actual IDEA/GWT and Linux systemd/UDS evidence has separate scope;
none of these contracts certify full component applicability, bridge health,
final write release or a general unguarded boot.

For an authorized partial-failure forward source, the inverse must still have an
exact CM_APPLIED proof and encrypted applied CM. Normal baseline, key/format,
unit and complete file-set grants remain independent; the original forward
`cmApplication` stays null. The nonempty-original continuation has actual scoped
evidence in console review `partial-source-completion-20261107.md` (ff72eb79).
