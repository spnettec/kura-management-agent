package org.eclipse.kura.management.agent.core;

import org.eclipse.kura.management.agent.model.CommandEnvelope;
import org.eclipse.kura.management.agent.model.ReplyEnvelope;

public interface CommandExecutor {
    ReplyEnvelope handle(CommandEnvelope command);
}
