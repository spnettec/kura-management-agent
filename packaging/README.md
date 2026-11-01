# Independent Rust agent package

This is an explicit, observation-only package candidate for Ubuntu 24.04+.
It installs `/usr/bin/yofc-management-agent` and the independent
`kura-management-agent.service`. It does not start the service, enroll a gateway,
authorize a Kura user, or take ownership of any network interface during installation.
The Java/MQTT migration baseline remains in this repository.

## Source and binary inputs

The development Cargo mapping points to the console sibling. Release staging instead
requires a versioned `yofc-management-protocol-0.1.0.crate` and its reviewed SHA256:

```sh
python3 packaging/build.py source --protocol /path/to/protocol.crate \
  --sha256 REVIEWED_PROTOCOL_SHA256 --destination /new/source-directory
```

Build and test that directory on the target Linux platform with the pinned toolchain
and `--locked`. Staged Cargo files reference the included `vendor/` artifact and do
not need a sibling checkout. The manifest binds the original Rust source and staged
Cargo file to the protocol artifact. Local packaging does not publish to a registry.

```sh
python3 packaging/build.py deb --binary /path/to/linux/yofc-management-agent \
  --sha256 REVIEWED_BINARY_SHA256 --architecture arm64 --version 0.1.0~candidate1 \
  --source-manifest /new/source-directory/source-manifest.json \
  --destination /new/package-directory
```

Packaging requires Python 3.12+, readelf and dpkg-deb. The ELF architecture and glibc
requirements are checked; Mach-O or a binary requiring glibc newer than 2.39 is refused.
The runtime pre-depends on Python because the preinst script uses its standard library.
All payload entries are root-owned; keys, gateway identity and state are absent from
the archive. Each maintainer script embeds its own lifecycle code so purge works
after ordinary removal of the program payload.

## Explicit identity and local authorization

First register a unique gateway and client certificate with the intended console
using its enrollment process. The current prototype provides an administrator CLI.
Installing an agent package never creates that registration. Copy the resulting CA,
client certificate and root-owned mode-0600 private key to the gateway, then run:

```sh
sudo kura-agent-setup import-identity --endpoint https://console.example:8444 \
  --gateway registered-gateway --ca /private/ca.pem --cert /private/agent.pem \
  --key /private/agent.key
sudo kura-agent-setup check
sudo kura-agent-setup activate
```

Import validates the client certificate chain and matching private key before writing
root-only `/etc/kura-management-agent/`. Identity now records
`AGENT_BINDING_GENERATION=1`. Repeating the same import while stopped preserves local
authorization. An existing different console/identity or interrupted import is refused.
A pre-generation same-center identity can be upgraded only by explicit
`sudo kura-agent-setup migrate-binding-generation`; missing or changed generation blocks
startup. This persistent generation is deliberately separate from runtime connection
epochs.

A privileged gateway-local rebind is available only after unsettled side effects are
resolved:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup transfer-identity --endpoint https://new-console.example:8444   --gateway registered-gateway --ca /private/new-ca.pem --cert /private/new-agent.pem   --key /private/new-agent.key --expected-generation 1 --operator 'local-admin'
sudo kura-agent-setup check
sudo kura-agent-setup activate
```

The command requires the exact current generation, validates the new chain/key pair,
backs up the prior identity and writes an audit receipt under state, then increments
`AGENT_BINDING_GENERATION`. It never carries a configured network writer and never
deletes execution history. Normal import from another center remains refused. Signed
cross-center authorization, external approval and certificate rotation workflows remain
separate unfinished work.

Kura Web credentials are independent of this identity. The default invalid UID
`4294967295` grants no Kura account access. To allow the separately packaged
unprivileged Kura JVM to register its bridge:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup authorize-kura --user kura-netplan
sudo kura-agent-setup activate
sudo systemctl start kura-netplan.service
```

The command records the actual `kura-netplan` UID and adds only the service-scoped
`SupplementaryGroups=kura-management` drop-in. Restart an already running Kura
explicitly to apply it. It does not add a login user to a group or grant network write
delegation. UID drift or an externally modified authorization file prevents startup.
Both agent and Kura interface allowlists remain empty. The packaged service has an
empty capability bounding set; this candidate does not authorize network writes.

Activation releases its setup lock before waiting for systemd because ExecStartPre
reacquires it to validate identity. Import and authorization refuse a service in
`activating`, `active` or `deactivating`, even when its main PID has not appeared yet.

## Retention and limits

Upgrade and ordinary removal stop the packaged service; reactivation is explicit.
Ordinary removal preserves `/etc/kura-management-agent/`,
`/var/lib/kura-management-agent/`, logs, identity and Kura authorization. Reinstallation
recognizes the retained marker and reuses the same identity and data.

Purge removes only those agent directories and its unchanged authorization drop-in.
It leaves the system group, Kura data and all OS network configuration in place.
Any configured writer, unsettled network journal, confirmed network configuration,
or modified authorization requires explicit handover before lifecycle changes.
Do not remove state to evade these guards.

This candidate does not complete writer handover, production enrollment/transfer,
firewall, offline recovery, the release matrix or the full management redesign.
Environment-specific evidence and deferred checks are recorded in the console's
`docs/phase2-agent-package-validation-20261101.md`.
