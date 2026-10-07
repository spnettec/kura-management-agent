package org.eclipse.kura.management.agent.model;

import java.util.List;

public record FirewallTable(String name, List<FirewallChain> chains, List<FirewallRule> rules) {
}
