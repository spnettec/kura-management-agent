package org.eclipse.kura.management.agent.core;

import org.eclipse.kura.management.agent.model.ReplyEnvelope;

public final class ReplyBuilder {

    private ReplyBuilder() {
    }

    public static ReplyEnvelope success(String id, Object payload) {
        return ReplyEnvelope.success(id, payload);
    }

    public static ReplyEnvelope failed(String id, String errorCode, String errorMessage) {
        return ReplyEnvelope.failed(id, errorCode, errorMessage);
    }
}
