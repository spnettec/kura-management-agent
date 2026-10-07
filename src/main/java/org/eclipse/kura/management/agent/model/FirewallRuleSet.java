package org.eclipse.kura.management.agent.model;

import java.util.List;

public record FirewallRuleSet(String ipVersion, List<FirewallTable> tables) {
}
