package org.eclipse.kura.management.agent.mqtt;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.kura.management.agent.model.CommandEnvelope;
import org.eclipse.kura.management.agent.model.ReplyEnvelope;
import org.eclipse.kura.management.agent.core.CommandExecutor;
import org.eclipse.kura.management.agent.firewall.FirewallAdapter;
import org.eclipse.kura.management.agent.model.FirewallStatus;
import org.eclipse.kura.management.agent.model.ResourceUsage;
import org.eclipse.kura.management.agent.system.SystemAdapter;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

public class MqttClientManager {

    private static final Logger logger = LoggerFactory.getLogger(MqttClientManager.class);

    private final CommandExecutor commandExecutor;
    private final SystemAdapter systemAdapter;
    private final FirewallAdapter firewallAdapter;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String brokerUri = System.getProperty("mqtt.brokerUri", "tcp://localhost:1883");
    private final String tenantId = System.getProperty("agent.tenantId", "t-001");
    private final String gatewayId = System.getProperty("agent.gatewayId", "gw-001");
    private final String mqttUsername = System.getProperty("mqtt.username", gatewayId);
    private final String mqttPassword = System.getProperty("mqtt.password", System.getProperty("agent.secret", ""));
    private final long heartbeatIntervalSec = Long.getLong("agent.heartbeatIntervalSec", 30L);
    private MqttClient client;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "management-agent-heartbeat");
        thread.setDaemon(true);
        return thread;
    });

    public MqttClientManager(CommandExecutor commandExecutor, SystemAdapter systemAdapter, FirewallAdapter firewallAdapter) {
        this.commandExecutor = commandExecutor;
        this.systemAdapter = systemAdapter;
        this.firewallAdapter = firewallAdapter;
    }

    public void start() {
        try {
            String clientId = System.getProperty("mqtt.clientId", gatewayId + "-management-agent");
            this.client = new MqttClient(brokerUri, clientId, new MemoryPersistence());
            this.client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    onConnected(reconnect, serverURI);
                }

                @Override
                public void connectionLost(Throwable cause) {
                    logger.warn("MQTT connection lost: {}", cause == null ? "unknown" : cause.getMessage());
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) throws Exception {
                    CommandEnvelope command = objectMapper.readValue(message.getPayload(), CommandEnvelope.class);
                    ReplyEnvelope reply = commandExecutor.handle(command);
                    byte[] payload = objectMapper.writeValueAsBytes(withAuth(reply));
                    client.publish(replyTopic(), payload, 1, false);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    // No-op.
                }
            });

            MqttConnectOptions options = new MqttConnectOptions();
            options.setAutomaticReconnect(true);
            options.setCleanSession(true);
            if (!mqttUsername.isBlank()) {
                options.setUserName(mqttUsername);
            }
            if (!mqttPassword.isBlank()) {
                options.setPassword(mqttPassword.toCharArray());
            }
            options.setWill(statusTopic(), offlineStatusPayload(), 1, false);
            this.client.connect(options);
            scheduler.scheduleAtFixedRate(this::publishStatusQuietly, heartbeatIntervalSec, heartbeatIntervalSec,
                    TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to start MQTT agent", e);
        }
    }

    public void stop() {
        scheduler.shutdownNow();
        try {
            if (client != null && client.isConnected()) {
                publishStatus(false);
                client.disconnect();
            }
        } catch (Exception e) {
            // Shutdown should not block process exit.
        }
    }

    public CommandExecutor getCommandExecutor() {
        return commandExecutor;
    }

    private String commandTopic() {
        return "mgmt/%s/%s/cmd".formatted(tenantId, gatewayId);
    }

    private String replyTopic() {
        return "mgmt/%s/%s/reply".formatted(tenantId, gatewayId);
    }

    private String statusTopic() {
        return "mgmt/%s/%s/status".formatted(tenantId, gatewayId);
    }

    private void onConnected(boolean reconnect, String serverURI) {
        try {
            client.subscribe(commandTopic(), 1);
            publishStatus(true);
            logger.info("MQTT {} to {} and subscribed to {}", reconnect ? "reconnected" : "connected", serverURI,
                    commandTopic());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialize MQTT session", e);
        }
    }

    private void publishStatus(boolean online) throws Exception {
        long now = System.currentTimeMillis();
        ResourceUsage resources = systemAdapter.getResourceUsage();
        FirewallStatus firewallStatus = firewallAdapter.getFirewallStatus();
        Map<String, String> services = new HashMap<>(systemAdapter.getServiceStates());
        services.put("firewall", firewallStatus.serviceState());
        Map<String, Object> envelope = withAuth(Map.of(
                "id", "status-" + now,
                "type", "status.report",
                "ts", now,
                "version", 1,
                "tenantId", tenantId,
                "gatewayId", gatewayId,
                "payload", Map.of(
                        "online", online,
                        "system", systemAdapter.getSystemInfo(),
                        "resources", Map.of(
                                "cpu", resources.cpuPct(),
                                "mem", resources.memPct(),
                                "disk", resources.diskPct()),
                        "firewall", firewallStatus,
                        "services", services)));
        client.publish(statusTopic(), objectMapper.writeValueAsBytes(envelope), 1, false);
    }

    private byte[] offlineStatusPayload() throws Exception {
        long now = System.currentTimeMillis();
        Map<String, Object> envelope = withAuth(Map.of(
                "id", "status-" + now,
                "type", "status.report",
                "ts", now,
                "version", 1,
                "tenantId", tenantId,
                "gatewayId", gatewayId,
                "payload", Map.of("online", false)));
        return objectMapper.writeValueAsBytes(envelope);
    }

    private Map<String, Object> withAuth(Object envelope) {
        @SuppressWarnings("unchecked")
        Map<String, Object> values = objectMapper.convertValue(envelope, Map.class);
        if (!mqttPassword.isBlank()) {
            values.put("auth", Map.of(
                    "type", "shared-secret",
                    "username", mqttUsername,
                    "secret", mqttPassword));
        }
        return values;
    }

    private void publishStatusQuietly() {
        try {
            if (client != null && client.isConnected()) {
                publishStatus(true);
            }
        } catch (Exception e) {
            // The next scheduled heartbeat will retry after the MQTT client reconnects.
        }
    }
}
