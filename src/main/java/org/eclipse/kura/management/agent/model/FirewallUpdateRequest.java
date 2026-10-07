package org.eclipse.kura.management.agent.model;

import java.util.List;

public record FirewallUpdateRequest(boolean enabled, List<Object> rules, boolean takeSnapshot) {
}
