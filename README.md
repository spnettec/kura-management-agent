# Kura Management Agent

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
