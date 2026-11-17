# Independent Rust agent package

2026-11-06 command proof extension: review `bootoutcome1` artifacts include original-command native decision records for boot tasks 16–19. Both agent lifecycle and Core preinst/postinst guards must understand the optional `commandDecisions`/`issuedCommand` metadata before this optional capability is activated. Legacy records remain valid; unknown/unlinked decisions are retained. See [the exact proof contract](../docs/ordinary-boot-task-outcome-v1.md). This remains a review candidate, not a formal release or full Kura recovery certification.

2026-11-06 optional boot-policy extension: `AGENT_ORDINARY_BOOT_REQUEST` is absent by default. A locally provisioned private fixed request can expose admin-only UDS and center tasks 15–19; callers cannot choose commands or units. The default service sandbox does not grant these system writes. `ordinary-boot.conf.example` is a separately reviewed example, never automatically installed. Preserve read-only sealed inputs and use only the required writable paths. See [the contract](../docs/ordinary-boot-remote-v1.md) and console `docs/reviews/center-ordinary-boot-20261106.md`. Current `centerboot2` deb/ELF are review artifacts; original Orb packages were not upgraded, and Parallels only extracted the deb.

> 2026-11-05 常驻首次接收后端：默认不设置 `AGENT_KURA_ENROLLMENT_DIR`，不会从Kura读取私钥。明确设置固定暂存目录并核定 `AGENT_KURA_UID` 后，已注册Kura可请求首次接收；私钥仍由Kura Java后端生成，成功后远程仍关闭。该目录授权独立于普通开关授权。已有身份不可用此入口替换；候选/回执和未决标记不得删除。完整合同与当前验证边界见 `../kura-management-console/docs/live-agent-enrollment-v1.md`（工作空间路径）。未发布新包、未升级原Orb服务。

This is an explicit package candidate for Ubuntu 24.04+; full release acceptance
remains pending. Network write delegation requires separate authorization.
It installs `/usr/bin/yofc-management-agent` and the independent
`kura-management-agent.service`. A clean installation starts the local-only agent
without TLS identity; remote management stays off. It does not enroll a gateway,
authorize a Kura user, or take ownership of any network interface during installation.
Reconfiguration preserves settings and does not implicitly restart a stopped service.
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
not need a sibling checkout. The schema-2 manifest binds Rust, runtime resources,
packaging code and service files to the protocol artifact and records every extracted
protocol file. The export includes its own packaging tools. Deb creation rechecks
the complete source set; an exported build also rechecks its vendored protocol tree.
Changed or omitted inputs are refused. Local packaging does not publish to a registry.

```sh
python3 packaging/build.py deb --binary /path/to/linux/yofc-management-agent \
  --sha256 REVIEWED_BINARY_SHA256 --architecture arm64 --version 0.1.0~candidate1 \
  --source-manifest /new/source-directory/source-manifest.json \
  --bridge-bundle /path/to/org.eclipse.kura.management.bridge.jar \
  --bridge-sha256 REVIEWED_JAVA_BRIDGE_SHA256 \
  --destination /new/package-directory
```

Packaging requires Python 3.12+, readelf and dpkg-deb. The ELF architecture and glibc
requirements are checked; Mach-O or a binary requiring glibc newer than 2.39 is refused.
The runtime pre-depends on Python because the preinst script uses its standard library.
All payload entries are root-owned; keys, gateway identity and state are absent from
the archive. Each maintainer script embeds its own lifecycle code so purge works
after ordinary removal of the program payload.

## Explicit identity and local authorization

Clean installation writes only a private local `agent.env`; it generates no TLS key.
`sudo kura-agent-setup init-local` provides the same guarded initialization explicitly.
Missing settings alongside retained state are a recovery condition, never a new install.
The agent can remain unbound indefinitely while its local status/recovery functions run.

Existing bound deployments without a remote decision must be stopped and explicitly
migrated with the reviewed candidate setup utility before activation:

```sh
sudo kura-agent-setup migrate-remote-control --enabled --operator local-admin
# Or choose --disabled explicitly when that is the intended previous state.
```

This command writes one durable revision/decision with the operator identity and
leaves the old identity, settings and journals intact. It refuses existing decisions
or unsettled work. It does not silently reset the state on upgrade. Current installations
use the local status/control API for later changes. Keep a verified candidate utility
available before upgrading older packages that do not yet contain this command.

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
First import into a clean local installation preserves its local choices and disabled
remote decision, retaining `local-enrollment-before.env`. An interrupted import keeps
its marker and backup and blocks startup/retry; do not delete that evidence to retry.
Import does not enable remote management. GWT identity delivery remains a separate
pending product workflow; this CLI accepts an already issued matching certificate/key.

Remote switch recovery now has local administrator UDS methods `remote.recovery-status`
and `remote.resolve-disabled`. Pass the exact returned observation (revision and file
digests) to resolve; this archives evidence and creates a new OFF decision. It never
replays an unknown switch, accepts an ON choice, or clears other subsystem journals.
Registered Kura peers cannot use these methods even with ordinary switch delegation.
An uncertain reply requires a fresh inspection, never an automatic resend. Both pending
switch and pending resolution journals block package/identity maintenance. A dedicated
operator CLI/UI wrapper remains pending; do not delete either journal to recover.
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
deletes execution history. Normal import from another center remains refused. If the identity includes a registered
original-center Ed25519 signer (`transfer-signer.pem`), a short-lived signed token can authorize
one explicit rebind. Generate the signer with `yofc-management-console generate-transfer-key`,
issue a token with `issue-gateway-transfer`, then pass `--authorization-token` to
`kura-agent-setup transfer-identity`. The token binds both generations, gateway IDs, endpoints,
new CA/client certificate hashes and a maximum 15-minute expiry. Before changing identity, setup
durably records the transfer ID, exact raw-token SHA256, signer SHA256, exact claims and operator
under `transfer-token-uses/`. If installation is interrupted after that record, the same token is
not retried; request and approve a new token. A signed transfer has been validated against an
independent logical center with separate PostgreSQL, trust anchor, process and ports on one test VM. For an identity imported before signer support, register the original-center
public key explicitly while stopped:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup register-transfer-signer --public-key /private/transfer-signer.pub   --expected-generation 2 --operator 'local-admin'
```

Registration is generation-bound, refuses a different signer, and writes an auditable receipt.
To replace that signer without undefined recovery, first issue
`yofc-management-console issue-transfer-signer-rotation` using the current private signer, then run
`kura-agent-setup rotate-transfer-signer` while stopped. The agent verifies a one-time token signed
by the current key, binds both SPKI SHA256 values/generation/operator, durably records its use, backs
up the old signer and token, then atomically replaces the key. Certificate rotation remains separate
operational work.

Kura Web credentials are independent of this identity. The default invalid UID
`4294967295` grants no Kura account access. To allow the separately packaged
unprivileged Kura JVM to register its bridge:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup authorize-kura --user kurad
sudo kura-agent-setup activate
sudo systemctl start kura.service
```

The command records the actual `kurad` UID and adds only the service-scoped
`SupplementaryGroups=kura-management` drop-in. Restart an already running Kura
explicitly to apply it. It does not add a login user to a group or grant network write
delegation. UID drift or an externally modified authorization file prevents startup.
Both agent and Kura interface allowlists remain empty. The packaged service has a
`CAP_NET_ADMIN` bounding set, runs as Root with `NoNewPrivileges`, and excludes
Kura credentials and the Root key-service directory. This is not full privileged
broker acceptance. Allowlists and writer grants remain empty by default; installation
does not authorize network takeover. The retained compatibility profile accepts
`--user kura-netplan` only for its own `kura-netplan.service`. Both profiles check
the installed vendor service and effective systemd User before granting admission;
only one profile can be authorized. Later agent checks bind the UID and protected
drop-in without requiring a healthy/running Core unit. This administrator CLI is
not complete GUI installation/enrollment acceptance.

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

This candidate completes a fixture-level signed logical-center transfer, but does not complete
writer handover, production enrollment/external approval, token revocation, firewall, offline
recovery, the release matrix or the full management redesign. Separate-host and network-partition
transfer tests remain deferred.
Environment-specific evidence and deferred checks are recorded in the console's
`docs/phase2-agent-package-validation-20261101.md`.

## Network writer delegation and handover

Network writing is never implied by installation. Grant it explicitly while the
agent is stopped, after the network transaction journal is settled and no
confirmed state remains from a previous role:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup grant-network-writer --interfaces eth0,ens5 --operator 'local-admin'
sudo kura-agent-setup activate
```

Interface names are validated (non-empty, unique, Linux-name bounded) and the
command refuses to run while another writer list or a confirmed state is still
installed — hand the previous role over first. Package lifecycle remains blocked
while a writer is installed.

Returning the writer to the system is explicit and auditable:

```sh
sudo systemctl stop kura-management-agent.service
sudo kura-agent-setup handover-network-writer --operator 'local-admin'
sudo kura-agent-setup activate
```

By default the persisted managed Netplan file (`/etc/netplan/90-yofc-managed.yaml`)
is kept so the system continues from the last confirmed configuration; the agent
only archives its confirmed state (with a receipt under
`/var/lib/kura-management-agent/network/handovers/<n>/`) and clears the writer
list, which also unblocks purge. `--discard-config` additionally deletes the
managed file, but only when it still matches the confirmed content byte for
byte; a drifted file must be resolved first. An unsettled network transaction
refuses handover.

## Firewall (own nftables table)

The agent manages firewall state in its own table `inet yofc_kura` only: full
candidate generation (input-chain allow list: tcp/udp ports with explicit
IPv4/IPv6 source prefixes, policy drop|accept), `nft -c` validation before
journaling, one atomic `destroy table` + declaration batch (never a global
flush), and JSON read-back verification before entering the confirm window.
Confirm/rollback reuse the explicit transaction pattern (30..=300s window,
token-bound, startup/deadline auto-rollback). Foreign firewall managers
(ufw/firewalld/docker/iptables/libvirt) are detected from `nft -j list ruleset`
and refused rather than auto-taken-over. Local admin peers drive it over the
UDS socket with `firewall.status|prepare|apply|confirm|rollback`; the packaged
unit grants exactly `CapabilityBoundingSet=CAP_NET_ADMIN`. The system
`/etc/nftables.conf` and the nftables service stay untouched, and port
forwarding/NAT plus the Kura firewall adapter remain future work.

## Offline recovery (stage v1)

The stage-v1 scope below remains historical artifact/unit evidence. The opt-in
Java CM inverse, retained file-set compensation and guarded ordinary startup now
have separate development contracts. The latest boundary is
[guarded ordinary startup](../docs/guarded-normal-startup-v1.md); it remains
nonterminal and does not certify a self-contained recovery release. No fixed
startup or baseline format grant is installed or enabled by default.

Recovery of a stopped Kura runs as an explicit, compensated transaction and is
**disabled by default**: it exists only when `AGENT_RECOVERY_UNITS` names the
recoverable unit(s) (bounded `.service` names) and optionally
`AGENT_RECOVERY_SNAPSHOT_DIR` overrides `/opt/eclipse/kura/user/snapshots`.
A local admin uploads one opaque artifact (`recovery.upload`, staging quotas
32MiB/64MiB/128 files, 0600 create-only), prepares it
(`recovery.prepare` with the exact SHA256 and an allowlisted unit), and executes
(`recovery.execute`, token-bound). Execution walks
STAGED→VALIDATED→STOPPING→BACKED_UP→COMMITTING→STARTING→VERIFYING→SUCCEEDED:
the unit is stopped and confirmed inactive, the snapshot directory is backed up
with a file manifest, the artifact is placed as `snapshot_<max+1>.xml`, the unit
restarts, and verification re-checks liveness plus the placed bytes. Any failure
compensates (hash-proven candidate removal, backup restore, restart) ending
FAILED or RECOVERY_REQUIRED, and a non-terminal journal is compensated at agent
startup. At this stage the artifact is opaque: no XML/encryption/factory
semantics and no Kura business-health verification yet — see
docs/evidence/offline-recovery-20261103.json for the validated boundary.


### Optional real Java format validation (2026-11-05)

The Core-owned successor is described in [core-owned-snapshot-validation.md](../docs/core-owned-snapshot-validation.md).
Its schema 2 configuration contains no Java executable, JAR or key path. The agent
submits a read-only snapshot descriptor to the fixed Root socket; only Core's worker
reads canonical encryption credentials. This is a local candidate, with package/runtime
capability admission and GUI configuration still pending. Generation publication
continues to refuse an installed agent. The schema 1 file/default profile below is
retained for explicitly reviewed legacy installations; it must not be expanded to
grant the agent access to Core's canonical credentials.

Set `AGENT_RECOVERY_VALIDATOR_CONFIG` only to a reviewed absolute 0600 JSON file
(see `snapshot-validator.json.example`). The canonical Java executable, standalone
JAR and adjacent `lib/` JARs must be regular non-linked files owned by root or the
agent user, without group/other write permission, in similarly controlled parent
directories. The bounded closure is fingerprinted together with the configuration
and selected key in the private transaction journal. Changed inputs are refused
before another Java launch; the public API never returns that private fingerprint.
The Java process has a fixed argument list, a cleared environment, bounded heap,
CPU/thread configuration, output and 30-second deadline. Child stderr is not
forwarded. No shell, password value or key bytes appear in the invocation.

Select `mode` as `plain` or `aes-gcm`, `passwordPolicy` as `authenticated` or an
explicitly audited `legacy`, and `key` as `{"kind":"file","path":"/absolute/raw-key"}`
or the explicit existing default choice `{"kind":"default"}`. No key lookup,
generation, rotation or fallback is performed. The raw AES key file must remain
readable after Kura stops; do not point at Kura's transient systemd credential
mount. Provisioning that independent read grant is an operator/release prerequisite.
Do not expose Kura Web credentials to the agent. Tool files and keys stay read-only;
only the existing allowlisted snapshot/state paths are writable. The recovery
sandbox example bounds the agent and JVM together at 512 MiB/64 tasks; this is an
opt-in override, not a change to the base observation-only unit.

`recovery.prepare`, execution before stop, and execution after confirmed stop each
call the real Java validator and match the artifact SHA, exact report and pinned
configuration. No validation failure may publish a candidate. Before stop it
rejects without unit mutation; after stop the existing compensation/RECOVERY_REQUIRED
path preserves staging and evidence. Prepared transactions cannot silently switch
between opaque and Java validation, including across agent restart. Reports and
receipts say `snapshot-format-and-unit-only`, carry the separate password/legacy
counts and retain `kuraRecoveryVerified=false`/`fullRecoveryVerified=false`.

Without this explicit config, the historical artifact/unit-only diagnostic remains
available only under the existing explicit unit allowlist, with its original
unverified label. Neither mode is a full Kura restoration product yet: controlled
core startup, factory replacement/removal, current external PID authority and actual
application receipts/business health are still pending. The Java tool is not yet
installed by this agent package; this increment must not be advertised as a formal
self-contained recovery release.

2026-11-06: fixed ordinary-unit handoff is independently opt-in; see [ordinary profile contract](../docs/ordinary-profile-handoff-v1.md). It does not enable a boot service or certify the complete Kura application surface.

2026-11-06: the packaged binary also provides `seal-ordinary-profile --request PRIVATE_JSON --output NEW_PRIVATE_GRANT`. This prepares a reviewed stopped unit without starting/enabling it or opening agent state; see the ordinary-profile contract for both direct Java and the explicitly selected Core packaged-background launcher. The Core optional argument hook has no agent startup dependency. The separate root-only `ordinary-boot prepare/execute/status/cancel/reconcile` CLI adopts reviewed native-unit enablement without starting or stopping Kura; see [boot adoption contract](../docs/ordinary-boot-adoption-v1.md). Its confirmation receipt is policy scope only; center tasks, non-native startup retirement and full Kura reboot acceptance remain pending.


2026-11-06: fixed Kura restart and host reboot now have separate optional local grants, typed center/UDS tasks, durable original-command reconciliation and a bilingual review UI. See [system control contract](../docs/system-control-v1.md). `kura-agent-setup configure-system-control --request PRIVATE_JSON --remote-disabled --operator NAME` seals the actual effective unit and pins, retains old grants/settings/audit and never starts/enables a unit. The supplied example has both actions disabled and placeholder hashes; explicit review is required. Interrupted installation, pending native transactions and changed receipts block maintenance, while retained system-task records block purge. This increment has host/native, PostgreSQL and mock-browser evidence only so far; new IDEA, OrbStack restart and Parallels reboot validation remain pending, and no new release artifact has been accepted.


2026-11-07: the default-off Rust local firewall now accepts an explicitly versioned
IPv4/IPv6 input, forward, DNAT, SNAT and masquerade candidate through the existing
administrator UDS transaction. NAT does not grant forwarding or change sysctl.
Historical v1 journals remain compatible; the complete table is read back and
mismatch observations are retained before rollback. See the shared workspace
[firewall v2 contract](../../kura-management-console/docs/firewall-transactions-v2.md).
Kura API/PID adaptation, center tasks/UI, writer ownership handoff, new management
path confirmation and early confirmed-only boot loading are still pending; this
increment does not enable a production firewall or certify a formal release.


### 2026-11-07 Kura 结构化防火墙候选 v3

本地管理员 UDS 已支持显式 schemaVersion=3 的两族独立策略、完整结构化端口/源端口范围、
CIDR/MAC/接口排除与通配、端口转发、自动/手工 NAT 来源及空协议语义。默认写闸门不变，
尚未增加 Kura UID 防火墙授权、新 provider/PID/GWT 接线、中心操作或实际早启部署。
合同与实际系统边界见 [v3 合同](../../kura-management-console/docs/firewall-kura-candidate-v3.md)
及 [本轮审查](../../kura-management-console/docs/reviews/firewall-kura-semantics-20261107.md)。

2026-11-07 a44da9fc：新增已注册 Kura UID 专用 `firewall.kura.*` 与
`AGENT_KURA_FIREWALL_WRITE=0` 默认关闭授权；准备/确认还必须开启既有全局防火墙写开关。
view/outcome 只读，原请求未知不得重发；事务按 UID、会话 owner 摘要及原始类型化输入摘要绑定，
终态覆盖前保留历史。撤销授权后仍允许持有原令牌的显式回滚，系统恢复闸门不解除。
可选 Kura provider 及原 API/PID 确认值投影已实施，NM 保留，agent 不成为 Kura 启动依赖。
这替代上文“adapter future work”的对应局部；GWT 写入确认界面、正式安装归属交接、NM 自动 NAT
和远程/早启/发行仍未交付。见 [provider 合同](../../kura-management-console/docs/firewall-kura-provider-contract-20261107.md)。
仅对明确支持的命名协议或0–255数值协议号编译，不接收任意 iptables/nft 文本。
