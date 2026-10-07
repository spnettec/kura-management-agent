package org.eclipse.kura.management.agent.model;

public record FirewallRule(String action, String chain, String expression) {
}
