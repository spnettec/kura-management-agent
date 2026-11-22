# Guarded live recovery health (development contract, 2026-11-06)

This optional, nonterminal phase observes the active guarded ordinary Kura JVM.
It does not complete recovery or release any writer. Kura can run without agent;
without a recovery request its optional bootstrap registers no recovery verifier.

Enable explicitly with the private administrator-owned JSON file selected by
`AGENT_RECOVERY_HEALTH_CONFIG`. The default is disabled. Schema 1 requires
`componentPids`, `checkIds` and `validForSeconds` (60–600). Both lists must contain
1–32 unique bounded names. Optional `additionalSelfPids` defaults to an empty
list and permits at most 32 unique names. The grant and its exact contents are
pinned in the plan and rechecked before execution and reopening.

The local administrator methods `recovery.health.prepare/execute` accept only
`transactionId` and `confirmToken`. Prepare requires the admitted normal-startup
ID/token and creates a separate health ID/token and immutable source anchor.
Execute persists intent before one read-only bridge call. It cannot accept a
command, path, unit, configuration values or a caller-supplied success predicate.
An ambiguous response is never automatically resent. A new observation after a
successful observation requires another explicit prepare and a new identity.

On Kura, `kura.management.recovery.verification.enabled=true` explicitly enables
the optional bridge capability `kura.recovery.verify`. It is absent from the
advertised methods by default and needs API configuration package 1.6. The
optional `RecoveryVerificationService` is registered only after authenticated
normal-load admission. Challenge identity, artifact SHA and nonce must match the
live admission. Reports contain no configuration values, passwords or paths.

The verifier compares the whole managed CM set through public ConfigurationAdmin
APIs before and after business checks. All original records, types and values,
including encrypted representations, must remain exact. Ordinary startup can
materialize a self-configuring singleton that was absent from the source set.
Such an addition is accepted only when its PID is explicitly in the grant,
ConfigurationRevisionService identifies it as SELF_CONFIGURING with a
component-owned view, and its entire actual CM record matches the current
ConfigurationService view. Factories, ordinary configurable components,
unlisted additions and differing views fail. The observed added PID list and
counts are reported separately; there is no general ignore list or default
exception for Console.

Selected component PIDs must belong to the authenticated source set and remain
registered. Each selected `RecoveryHealthCheck` ID must identify exactly one
registered provider using `kura.recovery.health.id`. Providers inspect real live
business state. Checks share one bounded daemon worker and a total one-second
deadline; missing, duplicate, throwing or hung checks fail. An interrupted hung
provider occupies the single worker rather than creating an unbounded thread
queue. CM is compared again after callbacks and the admission is rechecked.

Agent verifies the exact report identity, selected names, active normal MainPID,
source count, explicit additions, the configured framework level, ordinary-load admission,
write guard, CM equality and each business predicate. Its evidence also records
the agent instance and bridge epoch; an old bridge session cannot answer a new
request. A typed matching failed observation is retained with `verified=false`.
Unproven, interrupted or drifted execution stops all three recovery Kura units
and preserves RECOVERY_REQUIRED and the original evidence.

The private health grant can specify `frameworkStartLevel` as an integer from
5 to 9. It defaults to 5 for existing grants. Set it to the exact target of the
paired guarded-normal launcher. Preparation pins this setting along with the
selected checks. A report below or above the expected level is refused.

Success publishes a private create-only receipt and persists
AWAITING_HEALTH_COMPLETION with `selectedChecksVerified=true`,
`normalBootVerified=false`, `kuraRecoveryVerified=false` and
`awaitsExplicitCompletion=true`. The lifetime flag
`observationWithinValidityWindow` describes the past observation, not perpetual
current health. Reopening validates immutable source/receipt proofs and the same
active JVM without rerunning checks, restarting Kura or releasing writes.
Intentional test shutdown must be recorded separately; it is not a successful
later active-unit reopen.

Actual evidence and remaining product boundaries are recorded in the console
review `docs/reviews/recovery-health-20261106.md`. Selected fixture checks do not
certify every Kura component, external hardware, completion/release or an
unguarded ordinary startup.

For an authorized partial-failure forward source, health authenticates the
successful inverse's exact applied CM through normal admission. It never infers
successful forward application from the current JVM or downgrades failed-source
evidence. Whole-CM comparison, explicit self-PID additions and real selected
business callbacks remain mandatory. Ordered nonempty-original evidence is in
console review `partial-source-completion-20261107.md` (ff72eb79); this does not
certify an empty original CM or all production components.
