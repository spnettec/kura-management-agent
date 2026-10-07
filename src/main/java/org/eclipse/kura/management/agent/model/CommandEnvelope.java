package org.eclipse.kura.management.agent.model;

import java.util.Map;

public record CommandEnvelope(
        String id,
        String type,
        long ts,
        int version,
        String tenantId,
        String gatewayId,
        String correlationId,
        Map<String, Object> payload,
        Map<String, Object> meta) {
}
