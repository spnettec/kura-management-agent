package org.eclipse.kura.management.agent;

import java.util.concurrent.CountDownLatch;

import org.eclipse.kura.management.agent.config.ConfigAdapter;
import org.eclipse.kura.management.agent.config.DefaultConfigAdapter;
import org.eclipse.kura.management.agent.core.CommandExecutor;
import org.eclipse.kura.management.agent.core.DefaultCommandExecutor;
import org.eclipse.kura.management.agent.firewall.FirewallAdapter;
import org.eclipse.kura.management.agent.firewall.KuraFirewallAdapter;
import org.eclipse.kura.management.agent.mqtt.MqttClientManager;
import org.eclipse.kura.management.agent.network.KuraNetworkAdapter;
import org.eclipse.kura.management.agent.network.NetworkAdapter;
import org.eclipse.kura.management.agent.system.KuraSystemAdapter;
import org.eclipse.kura.management.agent.system.SystemAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AgentMain {

    private static final Logger log = LoggerFactory.getLogger(AgentMain.class);

    private AgentMain() {
    }

    public static void main(String[] args) {
        SystemAdapter systemAdapter = new KuraSystemAdapter();
        FirewallAdapter firewallAdapter = new KuraFirewallAdapter();
        NetworkAdapter networkAdapter = new KuraNetworkAdapter();
        ConfigAdapter configAdapter = new DefaultConfigAdapter();
        CommandExecutor commandExecutor = new DefaultCommandExecutor(systemAdapter, configAdapter, firewallAdapter,
                networkAdapter);
        MqttClientManager mqttClientManager = new MqttClientManager(commandExecutor, systemAdapter, firewallAdapter);

        log.info("Management agent skeleton started");
        mqttClientManager.start();
        Runtime.getRuntime().addShutdownHook(new Thread(mqttClientManager::stop, "management-agent-shutdown"));
        try {
            new CountDownLatch(1).await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
