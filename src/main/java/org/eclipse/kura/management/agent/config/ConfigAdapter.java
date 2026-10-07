package org.eclipse.kura.management.agent.config;

import java.util.List;
import java.util.Map;

import org.eclipse.kura.management.agent.model.ConfigDescriptor;
import org.eclipse.kura.management.agent.model.ConfigValueSet;
import org.eclipse.kura.management.agent.model.RollbackResult;
import org.eclipse.kura.management.agent.model.SnapshotResult;
import org.eclipse.kura.management.agent.model.UpdateResult;

public interface ConfigAdapter {
    List<ConfigDescriptor> listConfigs();
    ConfigValueSet getConfig(String pid);
    UpdateResult updateConfig(String pid, Map<String, Object> properties);
    SnapshotResult takeSnapshot(String reason);
    RollbackResult rollback(long snapshotId);
}
