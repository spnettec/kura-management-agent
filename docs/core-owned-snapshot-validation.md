# Core-owned snapshot validation candidate

The schema 2 validator delegates format/AEAD verification to Core's Root key service.
The internal configuration has only `schema`, `mode`, `passwordPolicy` and
`key: {"kind":"core"}`. It supplies no key, Java, JAR or socket path. Schema 1's
explicit file/default choices retain their prior behavior; a prepared proof cannot
silently change between profiles. There is no default-key or single-key fallback
from failed Core validation. Configuration through the deployment GUI and migration
of existing grants remain pending; this example is not a finished user setup flow.

The legacy Root agent uses `/run/kura-key-service/control.sock`. On Linux a
non-Root agent uses `/run/kura-snapshot-validation/control.sock` with no fallback.
Both use the same length-prefixed JSON protocol for validation:

- `core-validation-info`: exact schema 1/action fields; returns `CORE_CREDENTIALS_READY`
  with active/ring/cohort fingerprints and their canonical binding digest.
- `core-snapshot-validate`: exact schema 1/action, `snapshotSha256`, `mode`,
  `passwordPolicy`, `expectedBindingSha256`, plus one SCM_RIGHTS input descriptor.
  It returns `CORE_SNAPSHOT_VALIDATED`, the same binding, and the bounded existing
  validator report. It never returns key bytes, decrypted values or worker stderr.

The descriptor must be a nonempty private single-link regular file opened read-only,
at most 32 MiB, owned by the authenticated caller or the server-resolved `kurad` UID.
This covers agent-owned uploads and Kura-owned placed snapshots. The server copies
with `pread`, preserves the caller's offset, verifies stable file metadata/content,
and removes its private temporary copy after success or refusal. It accepts no path
for the input. No other operation accepts an input descriptor; malformed/truncated
or multiple ancillary descriptors are rejected and closed.

Core holds shared admission/provision locks, requires settled original operation
records and no maintenance fence, verifies the actual package cohort, then invokes
its fixed standalone Java worker with canonical single/ring credentials. It checks
the binding and input again after the worker. No operation UUID, backup, journal
settlement, Core start/stop or credential publication is created by validation.
An original UNKNOWN remains a barrier; this protocol cannot reconcile or retry it.

The agent authenticates the Root peer using kernel UDS credentials, validates exact
response shapes and report arithmetic, and binds its private proof to configuration
plus Core's binding. It rechecks both and the artifact after validation. Agent
construction only checks the schema 2 configuration; it does not contact Core, so
Core unavailability does not prevent agent startup. Failures during a recovery
transaction follow the existing staging/RECOVERY_REQUIRED rules.

On a configured native installation, local Root can validate a snapshot without
opening a recovery transaction. The packaged controller authenticates the actual
agent main process before sending the input:

```sh
kura-agent-setup validate-snapshot --input /path/to/snapshot.xml \
  --sha256 "$expected_snapshot_sha256" --mode plain --password-policy authenticated
```

The native agent's existing local socket receives one version-1 request frame
named `recovery.snapshot.validate`, with the exact parameters `size`,
`expectedSha256`, `mode` and `passwordPolicy`. Up to 32 MiB of raw snapshot bytes
follow the JSON frame. The client half-closes its write side when the input is
complete. The agent checks the size and digest before invoking Core with one
read-only FD. The reply contains a bounded `snapshotValidation` report and
`kuraRecoveryVerified: false`. The temporary input lives in the service runtime
directory and is removed after the check. The operation has no unit, transaction,
key-path or remote configuration parameters.

The installed native pair also offers `kura-agent-setup snapshot-inventory`.
The Root controller authenticates the running non-Root agent, which requests
`core-snapshot-inventory` on the native socket using the current Core binding.
The request takes neither a path nor a descriptor. The broker relays to a
separate cap-zero `kurad` worker with only a read-only view of the fixed Core
snapshot directory. The result contains the directory identity, bounded file
names, sizes, SHA-256 digests and ownership/mode. It marks the presence of
`.recovery-retained` without enumerating that private history. Unstable entries,
links, and non-private files fail the entire observation. Snapshot bytes and
keys stay within Core. The command does not grant snapshot writes, systemd
control, or offline recovery execution.

For controlled Java startup the agent emits `crypto.systemd.credentials=true`,
`crypto.key.sha256` and `crypto.ring.sha256` (`none` or a digest). These are exclusive
with legacy manifest key selections. The bootstrap uses only PID1's
`CREDENTIALS_DIRECTORY`, fixed credential IDs and the exact expected fingerprints.
The active credential must match the ring's writer key. Missing, mismatched, malformed
or unexpected ring credentials refuse startup; no canonical path is handed to agent.
This does not generate a complete controlled-start unit or authorize a new start.

The native agent's packaged Root pre-start inspector verifies its existing
installation, package source, effective unit and maintenance state. It publishes
a private attestation for that systemd invocation, boot and installation Root.
The dedicated socket admits only the live native unit's main process with its
exact UID and groups, zero capabilities and NoNewPrivileges. Core pins the Unix
peer and checks the attestation both before accepting input and after validation.
The dedicated socket is optional for native agent startup. The legacy control
socket retains its existing policy and the agent sandbox hides the canonical
credentials. Native recovery configuration, the full component lifecycle and the
GUI workflow still require release verification. The publisher's existing
`AGENT_GENERATION_UNAVAILABLE` gate remains in force.

Validation scope: disposable Linux native FD/storage tests and actual JDK 21 mixed
old/new-key snapshots; macOS Rust protocol/schema/start-manifest tests; and a fresh
systemd container with the actual Root service/JARs and a Linux Rust test executable
in the packaged agent sandbox (test executable/recovery capabilities/fixture writable
path are explicit overrides). That test checks startup with Root stopped, private
directory isolation, `kurad`-owned input FDs, repeated read-only proof checks and
rejected agent backup access. Main Core is not started. This is not a complete agent
deployment, controlled Core restart, customer/provider recovery or key retirement.
