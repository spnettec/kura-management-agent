# Fixed ordinary profile handoff v1

> 2026-11-06 center update: optional admin-only status/prepare/execute tasks are now connected under a separate default-off `AGENT_RECOVERY_ORDINARY_REMOTE` grant. See [center contract](../../kura-management-console/docs/ordinary-profile-center-v1.md) and [current system review](../../kura-management-console/docs/reviews/profile-handoff-center-20261106.md). Historical statements below that center integration is pending are superseded only for those three operations. Native handoff command-outcome proof, restart/reboot and full business verification remain pending.

2026-11-06. This extends explicit selected-check completion with an independently authorized transition to a pre-provisioned ordinary Kura service. It does not enable the unit at boot, install a distribution, rotate credentials, or certify all Kura components.

## Explicit local authority

The agent remains running. The ordinary Kura launcher has no `kura.recovery.request`, does not request key generation from the agent, and never waits for the agent during startup. Both the handoff and Java observer are disabled by default.

The existing local administrative UID policy applies. Two new methods accept exactly `transactionId` and `confirmToken`:

- `recovery.ordinary.prepare` authorizes against the previously committed completion transaction.
- `recovery.ordinary.execute` accepts the newly prepared handoff ID/token and starts the fixed unit once.

The caller cannot supply a command, path, unit, expected configuration value, snapshot policy, or health provider. Enable only reviewed fixed files through `AGENT_RECOVERY_ORDINARY_STARTUP_CONFIG`. An optional `AGENT_RECOVERY_ORDINARY_VALIDATOR_CONFIG` grants a separate format/key policy for the current snapshot. Without that variable, the original upload validator applies; the normal/legacy policy is never inferred automatically.

The private JSON grant uses schema 1 and these fields:

| Field | Meaning |
|---|---|
| `profileId` | Canonical `profile-<UUID>` identity |
| `unit` | Independently allowlisted fourth `.service`, distinct from the forward, inverse and guarded baseline units |
| `unitFile` / `jvmArgsPath` | Fixed absolute paths |
| `launcherKind` | `direct-java` by default; `packaged-background` explicitly selects the packaged shell contract |
| `launcherScriptPath` | Required only for `packaged-background`; fixed `start_kura_background.sh` |
| `unitDefinitionSha256` | SHA-256 of the normalized effective systemd definition |
| `timeoutSeconds` | Readiness deadline, 1–180 seconds |
| `validForSeconds` | Prepared authorization lifetime, 60–600 seconds |
| `componentPids` / `checkIds` | Nonempty, unique administrator-selected lists, at most 32 each |
| `profileFiles` | Reviewed immutable files with `path` and `sha256`, including launcher arguments, unit, runtime and every effective drop-in |

The grant is private. Files and parent directories must satisfy the existing trusted startup-file rules. JVM arguments use one literal token per line, optionally double quoted; escaping and nested `@` argument files are refused. Exactly one matching `-Dkura.management.ordinary.profile.id=...` and one `-Dkura.management.ordinary.verification.enabled=true` are required. Recovery request arguments are refused.

Direct Java remains the default. The independently selected `packaged-background` mode supports the Core distribution's `/bin/sh /fixed/path/start_kura_background.sh` invocation. It requires the supported optional-argument marker and actual `nohup java "$@"` argument path, pins the launcher and adjacent `gen_config_ini.sh`, and binds exactly one `KURA_JVM_ARGS_FILE` to the reviewed argument file. Extra shell arguments, another interpreter, an old launcher, an unpinned generator, or removal of this binding fail closed.

`EnvironmentFile` indirection is refused and `UnsetEnvironment` must include `JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS`. The packaged binding must not appear in `UnsetEnvironment`. All effective drop-ins remain pinned. The Core hook does not reference the agent: absent `KURA_JVM_ARGS_FILE`, its historical JVM arguments are retained. An explicit invalid file fails before generating configuration or starting Java. The literal shell `$@` is on a separate line from Maven `@...@` placeholders so resource filtering cannot swallow the memory settings.

For definition pinning, query `FragmentPath,DropInPaths,ExecStart,Environment,EnvironmentFiles,UnsetEnvironment,NeedDaemonReload` with `systemctl show --all`. Normalize missing `EnvironmentFiles` to empty, remove dynamic `ExecStart` data starting at ` ; ignore_errors=`, sort field names, and hash UTF-8 `key=value\n` lines. Unknown/duplicate fields, unpinned drop-ins, daemon reload drift and changed definitions fail closed. Administrator review must pin all relevant runtime inputs; this format is deliberately restricted rather than a general systemd launcher editor.

## Durable workflow

Preparation verifies the immutable parent completion proofs, the stopped forward/inverse/ordinary units, the current guarded baseline PID, the fixed profile and current complete snapshot inventory. The highest canonical numeric snapshot is validated by Java under the explicit ordinary policy. The source journal and grant are archived create-only.

Execution rechecks these facts and persists the issued intent before stopping the old three units. It rechecks the source after stopping, then calls `start` on the fixed ordinary unit once. It never rewrites or reuses an old recovery request.

The optional bridge method `kura.ordinary.verify` reads actual JVM PID, raw recovery-property absence, framework level, selected component registration and selected `RecoveryHealthCheck` providers. Reports bind the handoff, profile, nonce, observer instance and uninterrupted local bridge session. New execution requires report schema 2 with an ordered `providers` list (`id`, `available`, `unique`). A registered component PID alone does not prove DS activation or business initialization. A missing provider makes the report not ready; no business callbacks run until all requested providers are present. Startup unavailability/not-ready reads are bounded by the grant deadline.

Each provider must publish its service after its own application initialization has completed. The bridge cannot infer domain readiness from component names. Duplicate providers fail immediately, including while another startup condition is not ready. Throwing, hung or false checks fail once ready and are never polled into success; executor capacity and callback time remain bounded. A passing check must have an available unique provider. Schema 1 is accepted only to reconcile existing immutable historical receipts; it cannot authorize a new handoff. Failure retains the typed observation, stops the four managed units and requires explicit recovery.

The snapshot hash in the Java challenge/report is an approved context value, **not independent proof that this file was loaded**. The agent verifies source files and Java format evidence separately; the reviewed business providers establish their selected live assertions. All original source files must remain unchanged during handoff. Ordinary Kura may create new snapshots.

A verified observation is persisted before publishing the create-only terminal receipt. The terminal state is `ORDINARY_ACTIVE_APPROVED_CHECKS`, scope `administrator-selected-checks`, `ordinaryUnitHandedOff=true`, `kuraRecoveryVerified=false`. Both the running writer guard and packaging lifecycle guard recognize it. Historical parent completion remains a separate committed decision.

An interrupted issued handoff cannot automatically start again. Recovery accepts a matching durable terminal receipt without restarting or re-observing mutable post-completion state. Otherwise it records `RECOVERY_REQUIRED`, stops all four managed units, keeps evidence and blocks managed writes. A prepared but unissued handoff may remain prepared only while its original preflight still holds. No previous unit is automatically restarted as compensation.

After terminal completion, later legitimate snapshots, profile upgrades and intentional shutdown are not retroactively treated as a failed historical decision. Runtime enablement, boot adoption, subsequent restart/reboot task lifecycle, release packaging and the complete component/provider applicability matrix remain separate pending deliveries.


## Local installation seal (2026-11-06)

`yofc-management-agent seal-ordinary-profile --request PRIVATE_JSON --output NEW_PRIVATE_GRANT` runs without identity, database or UDS initialization. The request is the reviewed grant structure above with **no** `unitDefinitionSha256`; the command derives that value from the actual stopped, loaded unit. It rejects duplicate/unknown fields and existing destinations, verifies private ownership and every input hash, and publishes a private create-only grant with file/directory durability.

This command issues only bounded `systemctl show` queries. It does not start/stop/restart/enable/disable services, edit unit files, reload systemd, mutate agent state, or activate the resulting grant. The receipt's `unitStarted=false` and `unitEnabled=false` describe actions performed by the installer; they are not a certification of all boot dependencies or pre-existing enablement. Explicit local native-unit boot adoption is a separate operation described in [ordinary boot adoption](ordinary-boot-adoption-v1.md); center integration, non-native startup retirement and full Kura reboot acceptance remain pending.

For the packaged mode, a separately reviewed Core service drop-in may contain:

```ini
[Service]
Environment=KURA_JVM_ARGS_FILE=/etc/kura/ordinary.jvm.args
UnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS
```

Keep the ordinary JVM arguments with Kura-owned installation inputs, accessible to its configured service UID. They must survive removal of the agent. The agent's private JSON grant can reside under its own configuration directory. The ordinary argument file includes the fixed profile identity and explicitly enabled read-only observer; other JVM options remain administrator reviewed. This preparation does not alter the default NM backend, credentials, network/firewall write policy or installed Kura unit.

2026-11-07: explicit unissued-plan cancellation is now implemented (operation29/adminUDS), with current host validation and system stages still pending. See ordinary-handoff-cancellation-v1.md. Expiry alone leaves an otherwise unchanged unissued plan prepared for explicit cancellation; it does not stop the parent. The previously pending21/22 resolver and restart/reboot were separately validated in9104c438/4230b9b8; this does not reuse those binaries for cancellation.
