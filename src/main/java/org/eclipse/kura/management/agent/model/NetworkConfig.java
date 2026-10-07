package org.eclipse.kura.management.agent.model;

import java.util.List;

public record NetworkConfig(
        long collectedAt,
        String hostname,
        List<NetworkInterfaceInfo> interfaces,
        List<NetworkRoute> routes,
        List<String> dnsServers,
        String source,
        String errorMessage) {
}
