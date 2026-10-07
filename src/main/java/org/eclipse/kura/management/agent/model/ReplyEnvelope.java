package org.eclipse.kura.management.agent.model;

public record ReplyEnvelope(
        String id,
        String type,
        long ts,
        int version,
        String tenantId,
        String gatewayId,
        String status,
        Object payload) {

    public static ReplyEnvelope success(String id, Object payload) {
        return new ReplyEnvelope(id, "reply", System.currentTimeMillis(), 1, null, null, "success", payload);
    }

    public static ReplyEnvelope success(CommandEnvelope command, Object payload) {
        return new ReplyEnvelope(command.id(), "reply", System.currentTimeMillis(), command.version(), command.tenantId(),
                command.gatewayId(), "success", payload);
    }

    public static ReplyEnvelope failed(String id, String errorCode, String errorMessage) {
        return new ReplyEnvelope(id, "reply", System.currentTimeMillis(), 1, null, null, "failed",
                new ErrorPayload(errorCode, errorMessage));
    }

    public static ReplyEnvelope failed(CommandEnvelope command, String errorCode, String errorMessage) {
        return new ReplyEnvelope(command.id(), "reply", System.currentTimeMillis(), command.version(), command.tenantId(),
                command.gatewayId(), "failed", new ErrorPayload(errorCode, errorMessage));
    }
}
