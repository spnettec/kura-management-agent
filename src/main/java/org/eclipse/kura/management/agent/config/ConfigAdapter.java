package org.eclipse.kura.management.agent.config;

import java.util.List;

import org.eclipse.kura.management.agent.model.ConfigDescriptor;
import org.eclipse.kura.management.agent.model.RollbackResult;
import org.eclipse.kura.management.agent.model.SnapshotResult;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Gateway configuration backed by the Kura REST configuration service. Configuration payloads
 * are passed through as raw JSON (Kura ComponentConfiguration structures); the agent does not
 * interpret individual property values.
 */
public interface ConfigAdapter {

    List<ConfigDescriptor> listConfigs();

    JsonNode getConfig(String pid);

    JsonNode updateConfig(String pid, Object configuration);

    SnapshotResult takeSnapshot();

    List<Long> listSnapshots();

    RollbackResult rollback(Long snapshotId);
}
