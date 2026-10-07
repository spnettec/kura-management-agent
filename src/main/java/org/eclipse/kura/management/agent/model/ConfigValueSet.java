package org.eclipse.kura.management.agent.model;

import java.util.Map;

public record ConfigValueSet(String pid, Map<String, Object> properties) {
}
