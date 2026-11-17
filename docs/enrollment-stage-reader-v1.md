# Native Kura identity stage descriptor publisher — candidate

2026-11-17. Source and isolated Linux checks only. The Rust consumer, source/unit
pairing, packaging, activation and OS authorization UI are not yet connected.
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
`/opt/eclipse` and home directories, including paths created after startup. This
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

The Rust consumer must use this transport only under a separately reviewed
native enrollment grant. It must reject wrong peers/endpoints, framing,
extra/truncated ancillary data, wrong descriptor counts/labels, writable/nonregular
descriptors, wrong UID/mode/link count, oversized or changing files. All received
descriptors must close on every failure. Keep the existing independent copy,
manifest/PKCS8/CSR/certificate validation, candidate retention, shared change lock,
RUNNING/UNKNOWN checks, revision and durable original receipt semantics.

Native setup/package checks must pin the publisher script and exact protected
socket/service units. Installation alone must not enable the socket, authorize
enrollment or open a remote channel. The local UI must make UID/stage enrollment
authorization and remote switch authorization separate, with explicit maintenance
and activation actions. Do not stop an active agent implicitly or weaken the
inactive guard. Kura remains independently usable without agent/reader.

## Current evidence and retained boundaries

Nine Root Linux checks pass. Besides refusal cases, a real UID997 publisher with
zero effective/bounding caps and NNP1 delivered ten readonly descriptors to UID0
with only NET_ADMIN and NNP1; direct path reading was denied. Source bytes and
fingerprinted inode/owner/mode/link/size/mtime/ctime remained exact. The fixture
contained public synthetic bytes, not a business CSR or real private key.

Evidence is under the parent workspace's
`.management-close-20261116/source-cohort-20261117/enrollment-custody-20261117/`.
No original runtime, installed agent/unit/grant, Core canonical key or journal
was accessed or changed by these isolated checks. The native Core/GWT/agent
combination, OS UI, Rust integration, whole provider/launcher/install matrix and
all frozen parent items remain internal pending.

The unverified browser intent `combination-c-ebdbf564` stays reserved in its
original new fixture: no re-generation, replacement ID, signing, bind or channel
write is performed to validate this candidate. Old UNKNOWN and closed key
acceptance are untouched. External deferred remain only the original three
groups; this implementation work is not one of them.
