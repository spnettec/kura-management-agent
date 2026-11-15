# Joint NM/firewall coordinator writer — contract v1 (in progress)

2026-11-08, ZCode resume session, continuing the paused Codex ca9f292d batch.
The retained admission reader (`src/nm/transaction.rs`) and its evidence rules
are unchanged in meaning; this stage adds the writer that the reader anticipated.
Parent contract: `../../kura-management-console/docs/nm-firewall-coordination-v1.md`.

## Verified daemon facts (read-only introspection, Parallels Ubuntu 26.04, NM 1.54.3)

- `org.freedesktop.NetworkManager.Settings.Connection.VersionId` (type `t`,
  emits-change) is the persistent-profile compare-and-set token source. The
  `Settings` object has no VersionId property. Device `GetAppliedConnection`
  returns a separate applied version (`t`); on eth1 the applied version (3) and
  the stored profile VersionId (2) differed, so appliedVersion/hash must never
  substitute for the profile CAS token.
- `Settings.Connection.Update2` signature `(a{sa{sv}} u a{sv}) -> a{sv}`;
  `version-id` arg (since 1.44) rejects the update when the profile version
  differs; zero disables the check and is forbidden by the parent contract.
- `CheckpointCreate(ao devices, u rollback_timeout) -> o`, `CheckpointDestroy`,
  `CheckpointRollback`, `CheckpointAdjustRollbackTimeout` exist on the NM root;
  an unconfirmed checkpoint rolls back automatically after the timeout.
- Profiles on the probe VM were netplan-generated under
  `/run/NetworkManager/system-connections/`; the writer therefore treats
  `Flags != 0 || Unsaved` profiles as unsupported sources exactly like preview.

## Ownership and shared boundary

- Every mutating coordinator call executes under one
  `Guard::acquire(root, Subsystem::Nm)` held for the whole backend sequence.
  Firewall actions are performed under that same guard; the coordinator never
  recursively acquires `Subsystem::Firewall` and never mutates the firewall
  owner's table, journal or confirmed state.
- Before any side effect the coordinator binds the firewall owner's current
  revision, confirmed-text digest and journal state into the intent. Later
  operations re-check that binding; a foreign change fails closed.
- Automatic NAT rules live in the coordinator's own nft table `yofc_nm` with
  `comment "yofc nm auto"`. Independently managed tables and rules are never
  listed, modified or deleted. Forwarding is never enabled by the coordinator;
  NAT composition requires the system owner's forwarding to already be on.
- Journal layout (private 0600/0700, fixed UUID paths, no symlinks):
  `nm/transaction.json` (admission schema, extended with defaulted optional
  coordinator fields), `nm/intents/<op>.json` (immutable identity intent, SHA
  bound in the journal), `nm/intents/<op>.<action>.json` per durable pre-intent
  written before each backend side effect, `nm/receipts/<op>.json` terminal.
  The admission reader keeps validating the base identity fields with the same
  fail-closed rules; the added optional fields default so retained journals of
  the reader-only generation still parse.

## State machine (reuses the retained `State` enum order)

Prepared → CheckpointIntent → CheckpointCreated → ProfileIntent →
ProfileApplied → FirewallIntent → WaitConfirm → ConfirmDecided /
RollbackDecided → RollbackRunning → Committed / RolledBack / Cancelled;
RecoveryRequired marks evidence the reader cannot admit.

- Prepared: journal + immutable intent + proposal (fresh two-pass source
  capture under the guard; source digest must equal the caller's; typed
  candidate recompiled exactly like preview). No backend side effect.
- CheckpointIntent/CheckpointCreated: durable per-action pre-intent (checkpoint
  timeout, device list) then `CheckpointCreate(ao [], timeout)`.
- ProfileIntent/ProfileApplied: per-profile pre-intent binds profile path, UUID,
  observed `VersionId`, and the detached stored-candidate settings digest; then
  `Update2` with `version-id` = observed token (never 0) and flags 0; read-back
  re-reads `VersionId` (must increase) and re-hashes `GetSettings` (must equal
  the candidate digest). Any mismatch fails closed into RecoveryRequired.
- FirewallIntent/WaitConfirm: NAT pre-intent (rendered own-table text digest)
  then a single `nft -f -` apply of `yofc_nm` and kernel read-back verification;
  deadline recorded; state WaitConfirm.
- ConfirmDecided/RollbackDecided/RollbackRunning: explicit confirm destroys the
  checkpoint and verifies profile read-back again; explicit rollback runs
  `CheckpointRollback` (profiles and interfaces), then removes the own NAT
  table and verifies absence. Each terminal writes the matching receipt before
  the journal reaches Committed/RolledBack/Cancelled.
- Timeout expiry: a later observe with `deadline_ms` in the past verifies the
  live NM observation matches the recorded source digests (NM rolled the
  checkpoint back) and the NAT table is absent; matching marks RolledBack, any
  contradiction marks RecoveryRequired. Neither timeout nor reconnection ever
  authorizes another write.
- Lost results stay UNKNOWN: `prepare` refuses when a transaction exists at all
  (`OUTCOME_UNKNOWN: query original command`); recovery is a read-only
  adjudication over the original intent plus fresh observation, never a repair,
  replay or delete.

## API surface (this stage)

Local administrative UDS methods only, same boundary as inspect/preview
(registered Kura role rejected even with a shared UID):
`network.nm.prepare`, `network.nm.apply`, `network.nm.confirm`,
`network.nm.rollback`, `network.nm.status`. Writes require an explicit
`"writeEnabled": true` in the private NM configuration; without it every write
method returns UNSUPPORTED and observation stays available. Remote console
operations, protocol additions and center wiring are a later stage of the same
goal; no remote capability is added here.

## Validation boundary

Mocked-wire contracts prove the state machine, CAS, intents and fail-closed
behavior; they never claim real NM/nft acceptance. Native full regression,
strict all-target Clippy and a paired Linux build follow before any real
backend step. No deployment, no production NM/nft call, no commit/push.
