package org.eclipse.kura.management.agent.core;

import java.util.Map;

import org.eclipse.kura.management.agent.config.ConfigAdapter;
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
        if ("system.info".equals(command.type())) {
            return ReplyEnvelope.success(command, systemAdapter.getSystemInfo());
        }
        if ("config.get".equals(command.type())) {
            Object pid = command.payload().get("pid");
            if (pid == null) {
                return ReplyEnvelope.failed(command, "INVALID_REQUEST", "Missing pid");
            }
            return ReplyEnvelope.success(command, configAdapter.getConfig(String.valueOf(pid)));
        }
        if ("firewall.get".equals(command.type())) {
            return ReplyEnvelope.success(command, firewallAdapter.getFirewallConfig());
        }
        if ("network.get".equals(command.type())) {
            return ReplyEnvelope.success(command, networkAdapter.getNetworkConfig());
        }
        return ReplyEnvelope.failed(command, "INVALID_REQUEST", "Unsupported command type");
    }
}
