# Native Kura identity stage descriptor publisher — candidate

## 2026-11-17 actual non-Root native first enrollment

The later same-E runtime now establishes one bounded real enrollment with agent
codea3b13ea, Core50855bc and GWT6353614. The historical Root-profile counterexample
below remains applicable to those unchanged older profiles. This result does not
close typed privilege delegation, channel authorization or the full release matrix.

Original E CSR7c3361b3-3073-4394-be1c-e18d359525df was downloaded publicly and
signed outside the center. External CA key/certificate/serial files stayed exact;
no replacement CSR/key was generated. Two OpenSSL4 output-format preflight
failures occurred before any signing intent/dispatch and were retained. The
single actual signing produced client certificate SHA256
3681eb8603b4f432078929e673bdc5911c3366459612185964885e1265e79f1a.
GWT uploaded public files and staged them once, yielding stage SHA256
adf0acc7865866f5f86383531f4d80fa8c9f91842b16e7f1880fa32216776ca8.

The original expected remote revision and CSR/stage tuple were persisted before
one actual GWT first-bind call. Native Main9001/ticks19348899, UID/GID997 with all
five capability sets zero and NNP1, accepted it through the Root relay and paired
Kura publisher. Each socket accepted exactly one additional connection. Ten
independent native material files have matching hashes and different inodes from
the Core source. The existing Rust manifest/PKCS8/CSR/certificate validation ran
before publication; no separate live descriptor-loss fault was injected.

Candidate42e96468-bcf9-4940-9b81-0bc4fe70d13f, identity pointer, receipt,
identity-complete and completed-intent agree. Receipt sourceUid996,
bindingGeneration1, actor=kura-uid:996, operator=admin and all three public
acceptance fields match. Twenty native files are UID/GID997,0600 single-link in
0700 directories. Original Core CSR/stage files and context stayed exact, as did
Core6/local proof7/material proof5/current material2/native other5 assets.
Only the product remote decision changed to its new revision; enabled stayed
false. The earlier pre-bind filesystem observer checked an unused
management-enrollment path: that field is not proof of actual enrollment-directory
absence. Its original receipt and explicit correction remain, while the server's
first-bind admission and GWT canEnroll/bound state are separate evidence.

Core Main10205 and native Main9001 never restarted for signing/staging/binding.
Root operations/startups and native seven business tables remain zero. Same D
center registered only the public leaf certificate once:201, one gateway.register
SUCCEEDED audit, generation1, no bundle key/token, no first heartbeat or tasks.
Center enabled=true means registration acceptance, not the local remote switch.
The actual GWT still refuses remote enable because independent native Root switch
authorization is absent. No manual environment edits or implicit permission grant
were used. Current source maintenance also refuses this real staged/enrolled state;
retained identity/certificate maintenance must be implemented before its upgrade.

At15:53 UTC original3/private38/data6/processes7, personal25, reserved C9/processes/
counts and D29/Main3135 remained exact read-only. Full receipts are in the parent
source-cohort-20261117/native-enrollment-20261117 evidence directory; private keys
and credentials stay local-only. See console's native-enrollment-fd-checkpoint.json
and native-enrollment-fd-review-20261117.md. All12 parents and full provider/launcher/
install/migration/UNKNOWN/channel/broker/R017 matrices remain internal pending;
only the original3 external boundaries are deferred. Old UNKNOWN and closed key/
900-second acceptance were not replayed. Goal active, credits authorized, no push.

## Historical candidate and isolated checks

2026-11-17. Source and isolated Linux checks only. The Rust consumer now connects
under an explicit, exact native reader setting. Package mapping and Root source/unit
pairing are implemented candidates, along with durable local authorization and an
explicit activation path. No new package has been built, installed or activated;
the OS authorization UI and the runtime privilege boundary remain unfinished.
This is not a completed native enrollment or privileged-broker release.

The subsequent [separate-identity v2 candidate](native-agent-identity-v2-candidate.md)
adds a cap0 non-Root process gate and distinct Root-only/public relay roles.
Its disposable three-process interop passes, but packaging, authorization,
launcher mapping and actual systemd acceptance remain unconnected. The Root
runtime counterexample below remains applicable to the unchanged live profiles.

The installed agent runs as UID0 with only CAP_NET_ADMIN and NoNewPrivileges.
Kura's identity staging directory/files belong to its non-Root UID and remain
0700/0600. An isolated synthetic fixture confirmed EACCES for the agent-equivalent
process and successful reading by UID997 with zero capabilities. Do not add
global DAC capabilities, relax staging modes, or expose Core canonical keys to
make the delivery work.

## Fixed authority and read-only transfer

The candidate socket is `/run/kura-management-enrollment-reader.sock`, Root-owned
0600 and disabled until explicit local OS authorization. The socket-activated
publisher runs as the existing `kurad` account, without capabilities or Kura
startup dependencies. The agent's capabilities and credential/journal namespace
mask stay unchanged.

The native unit binds only the already existing native Core enrollment directory
at `/run/kura-enrollment-stage-input`. It hides `/etc/kura`, `/var/lib`,
`/opt/eclipse`, `/proc` and home directories, including paths created after startup.
Masking `/proc` also prevents reaching another same-UID Kura process's filesystem
through `/proc/PID/root`; hiding other UIDs alone would not establish this. This
unit layout still needs actual systemd/sandbox acceptance. It neither creates the
Core source directory nor migrates custom/legacy data roots. Other launcher/data
layouts need their own reviewed binding; no fallback to another directory.

The publisher accepts only a local Root peer. A systemd-activated listener is
owned by PID1/Root even when its accepted connection is handed to a non-Root
worker; the consumer must authenticate the protected native socket and paired
units/code, rather than expect its SO_PEERCRED to name the worker UID. The Root
agent's readonly system namespace must prevent it from replacing the native
endpoint. File descriptor metadata independently binds the source Kura UID.

The request is one bounded newline-terminated JSON object:

```json
{"version":1,"requestId":"canonical-lowercase-uuid","stageSha256":"64-lowercase-hex"}
```

There are no paths, commands, UIDs, private-key bytes or incoming descriptors.
Unknown/duplicate fields, extra frames and malformed data are refused. The
publisher opens fixed names with directory-relative O_NOFOLLOW operations,
checks 0700 directories and single-link 0600 regular files owned by its own UID,
verifies the requested manifest digest and completion markers, and retains
readonly/CLOEXEC descriptors. O_NOATIME avoids access-time updates on the owned
Linux sources. It does not execute, copy, chmod, chown or rewrite source data.

The response is a big-endian u32 length followed by at most 4096 JSON bytes. The
ten readonly descriptors accompany the first frame bytes as SCM_RIGHTS. JSON
contains only version, result, original request/digest, source UID and these
ordered labels:

1. private.pk8
2. public.der
3. request.pem
4. gateway.id
5. complete
6. certificates/client-chain.pem
7. certificates/issuer-ca.pem
8. certificates/console-ca.pem
9. certificates/manifest.json
10. certificates/complete

The key bytes never enter JSON, CLI arguments, browser/center results or logs.
Failure returns only `REFUSED`, without descriptors or private diagnostics.

## Required consumer and lifecycle work

The Rust consumer uses this transport only when the reader socket setting and
enrollment source are the exact native paths and the explicit Kura UID is non-Root.
There is no transport fallback on failure. It rejects wrong peers/endpoints, framing,
extra/truncated ancillary data, wrong descriptor counts/labels, writable/nonregular
descriptors, wrong UID/mode/link count, oversized or changing files. It requires
the one-shot publisher to close after exactly one response. All received
descriptors close on success and every failure. It retains the existing independent copy,
manifest/PKCS8/CSR/certificate validation, candidate retention, shared change lock,
RUNNING/UNKNOWN checks, revision and durable original receipt semantics.

Native setup/package checks now pin the publisher script and exact protected
socket/service units against the complete source manifest. Common and instance
overrides, changed ownership/modes/links and unpaired settings/grants are refused.
The candidate local authorization retains its original UUID, previous/requested
environment, grant, intent and completion receipt. Seven interrupted durable
boundaries and an environment switch failure remain UNKNOWN and block new IDs;
same-ID calls only observe the original outcome. The routine does not start any
unit or enable a remote channel. Explicit activation starts the reader socket
before the agent; package removal/upgrade stops the socket and loaded workers.
Native actual systemd/lifecycle acceptance is still pending.

Installation alone must not enable the socket, authorize enrollment or open a
remote channel. The local UI must make UID/stage enrollment
authorization and remote switch authorization separate, with explicit maintenance
and activation actions. Do not stop an active agent implicitly or weaken the
inactive guard. Kura remains independently usable without agent/reader.

## Current evidence and retained boundaries

Nine Python Root Linux checks pass. Besides refusal cases, a real UID997 publisher with
zero effective/bounding caps and NNP1 delivered ten readonly descriptors to UID0
with only NET_ADMIN and NNP1; direct path reading was denied. Source bytes and
fingerprinted inode/owner/mode/link/size/mtime/ctime remained exact. The fixture
contained public synthetic bytes, not a business CSR or real private key.

Thirty Rust enrollment/renewal checks pass, including descriptor rejection and
closure, framing, source UID and explicit native configuration checks. Two Root
interop entries are intentionally excluded from the ordinary run; an explicit
isolated parent test then executed its child successfully. That child had only
NET_ADMIN in effective/bounding capabilities and NNP1. Direct reading of UID997's
0700/0600 synthetic stage failed, while the actual non-Root Python publisher's
ten readonly descriptors allowed the Rust Store to create a private Root-owned
candidate and perform the unchanged manifest/PKCS8/CSR/certificate validation.
No identity pointer or pending transaction was published. Source file bytes,
inode, owner, group, mode, link count, size and all three timestamps remained
exact. This fixture generated only disposable test certificates and keys, and
does not establish the native systemd bind/sandbox, an enrollment grant, or a
business enrollment.

The expanded Python packaging run passed 116 checks, with two explicitly exported
historical native fixtures excluded. It includes 11 local authorization checks,
the nine publisher checks and existing identity/source/Core guard/system-control
checks. This is source and filesystem/command fixture evidence, not an installed
systemd acceptance result.

A subsequent purge guard retains completed local grants and original receipts
until an explicit verified archive. Fourteen relevant checks then passed,
including all 12 local authorization checks and two existing purge checks. These
overlap the earlier expanded run and must not be added to it as distinct coverage.

## Runtime isolation counterexample — blocks deployment

A public synthetic probe in the new combination fixture's `/var/lib` was hidden
through the agent's direct mount view. A process with the agent's UID0, only
NET_ADMIN and NNP1 could nevertheless read that public probe through the running
UID0, zero-capability key-service's `/proc/PID/root` mount view. The PID1 and
different-UID recovery service routes were refused. No key, HMAC, credential,
journal contents or business IDs were accessed. The one owned public probe was
removed; its creation/removal changes `/var/lib` directory timestamps.

Linux documents that [`/proc/PID/root` exposes the target process's mount view](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html).
The observed counterexample means direct-path masks do not establish the intended
Root/agent authority separation. Merely disabling dumps in the daemon would not
establish the whole boundary: normal exec can reset dumpability, and UID0 also
authenticates as Root to privileged IPC services. The runtime needs a separate
agent identity and reviewed typed privilege delegation. Do not deploy this
Root-actor candidate as a completed isolation fix. Keep that work internal pending
with the complete broker and native install/upgrade matrix.

Evidence is under the parent workspace's
`.management-close-20261116/source-cohort-20261117/enrollment-custody-20261117/`.
No original runtime, installed agent/unit/grant, Core canonical key or journal
was accessed or changed by these isolated checks. The native Core/GWT/agent
combination, OS UI, Root pairing/activation, whole provider/launcher/install matrix and
all frozen parent items remain internal pending.

The unverified browser intent `combination-c-ebdbf564` stays reserved in its
original new fixture: no re-generation, replacement ID, signing, bind or channel
write is performed to validate this candidate. Old UNKNOWN and closed key
acceptance are untouched. External deferred remain only the original three
groups; this implementation work is not one of them.
