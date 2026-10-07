package org.eclipse.kura.management.agent.core;

import java.util.Map;

import org.eclipse.kura.management.agent.config.ConfigAdapter;
import org.eclipse.kura.management.agent.config.KuraRestClient;
import org.eclipse.kura.management.agent.firewall.FirewallAdapter;
import org.eclipse.kura.management.agent.model.CommandEnvelope;
import org.eclipse.kura.management.agent.model.ReplyEnvelope;
import org.eclipse.kura.management.agent.network.NetworkAdapter;
import org.eclipse.kura.management.agent.system.SystemAdapter;

public class DefaultCommandExecutor implements CommandExecutor {

    private final SystemAdapter systemAdapter;
    private final ConfigAdapter configAdapter;
    private final FirewallAdapter firewallAdapter;
    private final NetworkAdapter networkAdapter;

    public DefaultCommandExecutor(SystemAdapter systemAdapter, ConfigAdapter configAdapter, FirewallAdapter firewallAdapter,
            NetworkAdapter networkAdapter) {
        this.systemAdapter = systemAdapter;
        this.configAdapter = configAdapter;
        this.firewallAdapter = firewallAdapter;
        this.networkAdapter = networkAdapter;
    }

    @Override
    public ReplyEnvelope handle(CommandEnvelope command) {
        try {
            return dispatch(command);
        } catch (KuraRestClient.KuraRestException e) {
            return ReplyEnvelope.failed(command, "KURA_REST_ERROR",
                    "Kura REST error " + e.getStatusCode() + ": " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return ReplyEnvelope.failed(command, "INVALID_REQUEST", e.getMessage());
        } catch (Exception e) {
            return ReplyEnvelope.failed(command, "INTERNAL_ERROR", String.valueOf(e.getMessage()));
        }
    }

    private ReplyEnvelope dispatch(CommandEnvelope command) {
        switch (command.type()) {
            case "system.info" -> {
                return ReplyEnvelope.success(command, systemAdapter.getSystemInfo());
            }
            case "config.list" -> {
                return ReplyEnvelope.success(command, Map.of("configs", configAdapter.listConfigs()));
            }
            case "config.get" -> {
                return ReplyEnvelope.success(command, configAdapter.getConfig(requireString(command, "pid")));
            }
            case "config.put" -> {
                String pid = requireString(command, "pid");
                Object configuration = command.payload().get("configuration");
                if (!(configuration instanceof Map<?, ?>)) {
                    throw new IllegalArgumentException("configuration object required");
                }
                return ReplyEnvelope.success(command, configAdapter.updateConfig(pid, configuration));
            }
            case "firewall.get" -> {
                return ReplyEnvelope.success(command, firewallAdapter.getFirewallConfig());
            }
            case "network.get" -> {
                return ReplyEnvelope.success(command, networkAdapter.getNetworkConfig());
            }
            case "snapshot.list" -> {
                return ReplyEnvelope.success(command, Map.of("snapshots", configAdapter.listSnapshots()));
            }
            case "snapshot.take" -> {
                return ReplyEnvelope.success(command, configAdapter.takeSnapshot());
            }
            case "snapshot.rollback" -> {
                Object id = command.payload().get("snapshotId");
                Long snapshotId = id instanceof Number number ? Long.valueOf(number.longValue()) : null;
                return ReplyEnvelope.success(command, configAdapter.rollback(snapshotId));
            }
            default -> {
                return ReplyEnvelope.failed(command, "INVALID_REQUEST", "Unsupported command type");
            }
        }
    }

    private String requireString(CommandEnvelope command, String key) {
        Object value = command.payload() == null ? null : command.payload().get(key);
        if (value == null || String.valueOf(value).isBlank()) {
            throw new IllegalArgumentException("Missing " + key);
        }
        return String.valueOf(value);
    }
}
