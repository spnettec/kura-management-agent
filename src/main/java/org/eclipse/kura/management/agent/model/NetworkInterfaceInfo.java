package org.eclipse.kura.management.agent.model;

import java.util.List;

public record NetworkInterfaceInfo(
        String name,
        String displayName,
        String macAddress,
        boolean up,
        boolean loopback,
        boolean virtual,
        boolean pointToPoint,
        int mtu,
        List<NetworkAddress> addresses) {
}
