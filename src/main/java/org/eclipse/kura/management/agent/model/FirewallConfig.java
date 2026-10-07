package org.eclipse.kura.management.agent.model;

import java.util.List;

public record FirewallConfig(
        boolean enabled,
        boolean running,
        boolean healthy,
        boolean packageInstalled,
        String serviceState,
        String systemdState,
        String healthMessage,
        long collectedAt,
        String source,
        String errorMessage,
        String ipv4Rules,
        String ipv6Rules,
        List<FirewallRuleSet> parsedRules,
        List<Object> rules) {
}
