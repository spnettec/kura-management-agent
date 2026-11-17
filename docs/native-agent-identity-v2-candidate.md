# Separate native agent identity — candidate v2

2026-11-17. Source, filesystem/command fixtures and disposable Linux process
interop only. These files are not yet mapped into a native deb or activated.
The Root profile from the previous candidate remains blocked from deployment as
a complete isolation result. See [the public-probe counterexample](enrollment-stage-reader-v1.md#runtime-isolation-counterexample--blocks-deployment).

## Authority split

The draft main unit uses the fixed non-login account `kura-management-agent`,
primary group `kura-management`, its separate reader group, zero effective,
permitted, bounding, inheritable and ambient capabilities, and NNP1. Kernel UID
separation prevents this main process from using a same-UID Root peer's process
filesystem or authenticating to privileged IPC as UID0.

The initial native profile supports observation and local channel control. Root
network/firewall/system-control/recovery and other unconnected capabilities are
explicitly refused, including a formerly accepted legacy TLS environment. They
need their own reviewed typed brokers and continuity/migration paths. There is
no runtime downgrade to the legacy Root profile on failure.

| Component | OS identity | Authority |
| --- | --- | --- |
| Kura stage publisher | existing Kura UID, cap0 | Fixed staged-identity names; readonly FD output to Root only |
| Enrollment relay | Root, cap0 | Authenticate one explicit agent UID/GID and relay the ten readonly FDs |
| Agent main | separate agent UID, cap0 | Own private runtime state and accepted client identity; no Core key/HMAC access |
| Root profile controller | Root | Root code/unit/identity checks and explicit provisioning/authorization; no implicit service stop |

The main's control socket, runtime directory and persistent state use new native
paths. Root administration uses `/var/lib/kura-management-agent-admin`, private
configuration uses `/etc/kura-management-agent-runtime`, and the protected public
identity is `/etc/kura-management-runtime/agent.json`. The main state is
`/var/lib/kura-management-agent-runtime`, and its control socket is
`/run/kura-management-agent-runtime/control.sock`. Do not remap an old data root
or recursively chown retained state. The draft unit deliberately omits persistent
`StateDirectory=` ownership adoption; the controller may assign only a known new
directory. The ephemeral runtime directory also differs from the legacy unit.

## Startup and narrow material delivery

Before creating a control socket, Rust requires the exact Root-owned public
identity, fixed UID/GID/paths, no unreviewed supplementary groups, zero capability
sets and NNP1. It checks the actual Root-owned, single-link program, source
manifest and native unit hashes. Unsupported delegation settings fail closed.
The Root pre-start inspection is an explicit fixed program; systemd's
[`+` command prefix](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
is used for that inspection only, while the daemon remains non-Root. Actual
systemd behavior and installed file pairing have not been accepted yet.

The agent endpoint is `/run/kura-management-agent-enrollment.sock`, Root-owned
0660 with only the dedicated reader group. Its parent remains Root-owned, so the
agent cannot replace the endpoint. The original publisher endpoint remains
Root-only 0600. Rust selects those two distinct roles explicitly: the publisher
endpoint is for a Root broker; the agent endpoint requires the exact native
identity and state root. No broad Root-or-non-Root peer match is added to the
Core key-service or GWT Root transport.

The relay accepts only its granted agent UID/GID. It parses the original bounded
UUID/digest request, connects only the protected fixed upstream, verifies the
Root peer, exact response/binding/FD metadata, and forwards readonly descriptors.
It does not read private FD contents. Both successful and refused paths close
received descriptors. Its draft unit masks `/etc`, `/var/lib`, `/opt/eclipse`,
`/run` and `/proc`, binding only the fixed Root grant and upstream socket. The
accepted client socket is inherited; other host IPC sockets are absent from
that proposed namespace. This unit sandbox still needs actual acceptance.

## Checks completed in this increment

- Three Rust identity/environment checks pass: wrong Root/user/path/group,
  excessive capabilities, NNP0 and unavailable delegation are refused.
- Eight Linux relay checks pass, including missing/duplicate/excess/truncated
  rights, writable/mismatched descriptors, Root peer refusal and an actual
  UID995/GID993 client. The relay does not advance source FD offsets itself.
- Public-only Linux controls show a UID0/NET_ADMIN/NNP1 process can read a public
  probe through a UID0/cap0 peer, while UID995 with either cap0 or NET_ADMIN/NNP1
  is denied. No real credential or Core data is opened.
- Nine native profile filesystem/command checks pass, including five durable
  publication interruptions, wrong interactive/Root/aliased account refusal,
  retained/empty native data refusal, original-UUID readonly observation,
  changed code/unit/config refusal, and missing marker refusal. The controller
  does not start units, create accounts or adopt legacy data in these checks.
- The changed enrollment transport retains 30 passing Rust enrollment/renewal
  checks; Root interop entries remain outside that ordinary run.
- A separately selected disposable Root-container parent and its non-Root child
  pass the complete publisher → Root relay → Rust Store path. Actual UID997/cap0
  publishes, Root/cap0 relays, and UID995/cap0/NNP1 consumes. The consumer cannot
  directly open the source. It validates the protected identity/unit/program
  files and performs the unchanged independent PKCS8/CSR/certificate checks,
  creating a UID995/0600 candidate without publishing identity/pending pointers.
  Source bytes, ownership/mode/link/inode/size and all three timestamps remain
  exact. Its program/source metadata is explicitly a filesystem test fixture,
  not a released source manifest or an installed package acceptance.

Evidence is in the parent workspace's
`.management-close-20261116/source-cohort-20261117/enrollment-custody-20261117/`.
All keys/certificates in the process fixture are disposable test material. No
original runtime, business CSR or old command ID is reused.

## Required work before deployment

Native account creation, durable package/profile selection, full source/payload
mapping and actual systemd/namespace acceptance remain pending. The controller's
current initializer supports only a clean, unbound profile and rejects a retained
legacy installation. Existing client identities, TLS import/CSR, execution DBs,
UNKNOWN/receipt continuity, state-loss detection/backup/restore and interrupted
upgrade/migration need explicit original-intent handling. Do not treat this
initializer as a migration or final state lifecycle implementation.

Native Kura UID and material authorization, independent remote-switch grant,
Root paired relay metadata, GUI maintenance/authorization/activation and full
R017 remain unconnected. The current pre-start configuration check permits only
the initialized capability set. Core's optional adapter launcher still needs
the protected native peer user/socket mapping; existing explicit legacy/dev
properties and all Root key checks must retain their exact scope. No active
Core/agent process or personal configuration is changed to test that mapping.

Complete privileged brokers, all provider/launcher/mode/resource/purge/platform
rows and all twelve frozen parents remain internal pending. Core Main's current
11 ambient/13 bounding caps and NNP0 are a separate unchanged obligation. External
deferred remain only NM/cloud-init/physical hardware, amd64 and disk-full/hard
power loss. The reserved `combination-c-ebdbf564` intent is not regenerated,
renamed or tested in another Root; closed key acceptance is not replayed.
