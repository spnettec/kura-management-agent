# Retained snapshot-file compensation (development contract, 2026-11-06)

This follows a proven agent CM inverse. It restores the complete original active
file inventory while retaining the forward and inverse candidate bytes, owners,
groups and permissions. It stops both fixed Kura units, never starts Kura and
never releases ordinary writes. Normal boot, bridge/business health and explicit
completion remain separate, unfinished gates.

Only local administrator UDS requests may use these two new methods. Existing
recovery, Java validator and independent inverse-startup grants must still match.
No caller can provide a directory, command, unit, archive name or source file.
Both methods use the recovery response budget of 600 seconds. OUTCOME_UNKNOWN
requires querying the original transaction; never resend an uncertain execution.

`recovery.snapshots.prepare` takes the inverse transaction ID and its token. It
requires the exact CM_APPLIED inverse proof and all sidecars, unchanged
source-journal anchors, the complete original snapshot-backup manifest and bytes,
and the exact active inventory (original files plus the two admitted candidates).
All original files, including retained `.bad` and other inventoried regular files,
are verified with their original metadata. Any foreign, missing or changed entry
rejects before unit stop or active-file movement. It returns a new `set-...` ID
and confirmation token and records SNAPSHOT_SET_PREPARED. No Kura unit is stopped
by prepare, and no active candidate is moved.

A private `.recovery-retained` subdirectory under the granted snapshot directory
holds the new artifacts. Its owner, private permissions and create-only ownership
marker are mandatory; an unrecognized directory with this name blocks inventory.
The exact directory is excluded from active inventory after those checks. Kura's
normal nonrecursive snapshot filename enumeration ignores this name. Using a
child of the existing snapshot grant keeps source and destination under the same
systemd writable bind mount; a state-directory archive could fail even when both
paths report the same underlying filesystem device.

`recovery.snapshots.execute` requires the new set ID/token, rechecks all evidence,
stops both fixed units and verifies again after stopping. It persists retention
intent before the first move. Each candidate is moved atomically without replacing
an existing destination (Linux renameat2/RENAME_NOREPLACE; macOS
renamex_np/RENAME_EXCL), and both directories are synced before recording its
per-file progress. Cross-mount movement is refused; no copy/unlink fallback is
used. Original backups, requests, plans, receipts, keys and journals remain intact.
The original active files are not rewritten because the transaction has proved
the complete baseline unchanged; unrelated or missing data is never guessed away.

After verifying the full original active inventory, both retained candidates and
all application evidence, it publishes a create-only SNAPSHOT_SET_RESTORED receipt
and enters AWAITING_SNAPSHOT_COMPLETION. Status still reports
`kuraRecoveryVerified=false`, `normalBootVerified=false` and
`awaitsExplicitCompletion=true`. Reopening agent checks the exact receipt, all
source/backup/application evidence, active files, retained candidate locations and
stopped units without starting anything. Ordinary writes and new uploads remain
blocked. This is file-set compensation, not terminal recovery success.

Any interruption, including a crash between atomic move and journal progress,
retains the files at their actual locations, stops both units and enters
RECOVERY_REQUIRED. It never automatically completes, reverses or replays a move.
There must be exactly one retained/live location for each candidate. An ambiguous
location, changed ownership marker, extra active file or changed proof remains
for explicit inspection. Snapshot-only rollback cannot settle this transaction.
Do not remove requests or start normally as a substitute for health/completion.

Unit contracts cover complete inventory/metadata preservation, no overwrite,
source/backup/live/anchor drift before stop, crash after the first real atomic
move, reopen failure without replay and continued write rejection. Exact native,
Linux and actual-sandbox evidence is recorded separately in the console review;
those scopes must not be inferred from unit fixtures.

## Partial-failure source continuity (2026-11-07, ff72eb79)

The original source may use the existing complete CM_APPLIED proof or the exact
partial-failure checkpoint authorized by the inverse profile's default-off
`allowPartialSource` grant. Both grades stay pinned through the source anchor and
file-set restoration. A partial source never gains a forward application record
or an inferred applied hash when its candidates are retained. Revoked authority
or changed failure evidence still blocks; no later file-set phase can replay the
original request or release writers. Guarded normal, selected health, explicit
completion and separate ordinary launch each retain their independent grants.
Actual ordered evidence is in console review `partial-source-completion-20261107.md`.
