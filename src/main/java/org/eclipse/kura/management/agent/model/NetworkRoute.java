package org.eclipse.kura.management.agent.model;

public record NetworkRoute(String destination, String gateway, String device, String protocol, String scope, String source, String raw) {
}
