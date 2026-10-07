package org.eclipse.kura.management.agent.model;

public record FirewallStatus(
        boolean enabled,
        boolean running,
        boolean healthy,
        boolean packageInstalled,
        String serviceState,
        String systemdState,
        String healthMessage,
        int ipv4RuleCount,
        int ipv6RuleCount,
        long collectedAt,
        String source,
        String errorMessage) {
}
