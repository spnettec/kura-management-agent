# Native Kura identity stage descriptor publisher — candidate

2026-11-17. Source and isolated Linux checks only. The Rust consumer now connects
under an explicit, exact native reader setting. Package mapping and Root source/unit
pairing are implemented candidates, along with durable local authorization and an
explicit activation path. No new package has been built, installed or activated;
the OS authorization UI and the runtime privilege boundary remain unfinished.
This is not a completed native enrollment or privileged-broker release.

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
