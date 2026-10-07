package org.eclipse.kura.management.agent.model;

import java.util.List;

public record SystemInfo(
        String hostname,
        String osVersion,
        String kernelVersion,
        String arch,
        String kuraVersion,
        String javaVersion,
        long uptimeSec,
        List<String> ipAddrs) {
}
