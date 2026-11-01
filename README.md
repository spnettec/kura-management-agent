# Kura Management Agent

2026-10-31 架构更新：本仓库后续迁移为独立开机启动的 Rust agent，合并有线网络、
防火墙、系统控制及 Kura 离线恢复能力。中心项目已统一为 `../kura-management-console/`，
完整范围与估算见 [完整改造方案](../kura-management-console/docs/management-redesign-plan.md)。
以下 Java/MQTT 使用说明属于 2026-10-31 迁移基线；2026-11-01 的 Rust/gRPC/UDS 原型见末节。

Lightweight gateway-side management agent skeleton.

The agent will connect to MQTT, publish status reports, receive management commands, call local Kura services, and publish replies.

Current skeleton includes:

- command envelope and reply envelope models
- command executor
- system adapter
- firewall adapter
- MQTT manager placeholder
- online heartbeat reports
- offline status reports through MQTT Last Will and graceful shutdown

## Development

Build the executable jar:

```bash
mvn package -DskipTests
```

Run locally against a broker on `localhost:1883`:

```bash
java -jar target/kura-management-agent-0.1.0-SNAPSHOT.jar
```

Run from the OrbStack `ubuntu` VM against the host broker:

```bash
java -Dmqtt.brokerUri=tcp://host.orb.internal:1883 \
  -Dmqtt.username=gw-001 \
  -Dmqtt.password=gw-001-secret \
  -jar target/kura-management-agent-0.1.0-SNAPSHOT.jar
```

Useful system properties:

```text
mqtt.brokerUri=tcp://localhost:1883
mqtt.clientId={gatewayId}-management-agent
mqtt.username={gatewayId}
mqtt.password={gateway secret}
agent.tenantId=t-001
agent.gatewayId=gw-001
agent.secret={gateway secret}
agent.heartbeatIntervalSec=30
```

## Rust implementation (2026-11-01)

The independent Rust executable is now implemented. The Java/MQTT commands above
remain the migration baseline. Build Rust with the pinned toolchain:

```bash
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

`packaging/agent.env.example` documents mTLS identity, UDS credentials and private
state paths. Network management defaults to observation only. An explicit interface
allowlist is required, and external/ambiguous Netplan ownership still refuses writes.
Unconfirmed candidates live under `/run/netplan`; confirmed configuration alone is
persisted under `/etc/netplan`. The agent independently handles expiry and startup
recovery while its center transport reconnects.

UNKNOWN network receipts can now be reconciled against an authenticated original
execution plan and a command-bound terminal business journal. Queries never replay
the network action; evidence that is missing or inconclusive keeps UNKNOWN. The
capability is `task.network-outcome.v1`. See the console repository's
`docs/network-outcome-reconciliation-v1.md` and
`docs/phase2-network-outcome-validation-20261101.md` for semantics and actual fault
injection evidence. Legacy journals without command markers still require a later
auditable recovery workflow.

The current network transaction contract and actual evidence live in the sibling
console repository: `docs/phase2-network-contract.md` and
`docs/phase2-validation-20261101.md`. This is not yet a Kura networking-provider
replacement or a complete release. The sibling protocol patch remains a development
mapping; explicit package source staging replaces it with a checksummed versioned
artifact and has been built and tested on Linux.

Explicit transfer of one reviewed networkd source is implemented, preserving
original permissions, unrelated interfaces and IPv6. Evidence and remaining limits
are in `docs/phase2-takeover-validation-20261101.md` in the console repository.
NM/cloud-init handover and a complete inventory of external writers remain pending.

An independent, observation-only Ubuntu deb candidate and explicit identity/UID
setup are now implemented; see [packaging instructions](packaging/README.md).
Installation never starts the agent or enrolls/takes over a gateway. Registration is
independent of Kura Web credentials, and an existing different console identity is
refused. Writer delegation and the complete production release remain unfinished.
