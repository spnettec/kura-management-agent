package org.eclipse.kura.management.agent.config;

import java.util.List;
import java.util.Map;

import org.eclipse.kura.management.agent.model.ConfigDescriptor;
import org.eclipse.kura.management.agent.model.ConfigValueSet;
import org.eclipse.kura.management.agent.model.RollbackResult;
import org.eclipse.kura.management.agent.model.SnapshotResult;
import org.eclipse.kura.management.agent.model.UpdateResult;

public class DefaultConfigAdapter implements ConfigAdapter {

    @Override
    public List<ConfigDescriptor> listConfigs() {
        return List.of(new ConfigDescriptor("org.eclipse.kura.net.admin.FirewallConfigurationService", false));
    }

    @Override
    public ConfigValueSet getConfig(String pid) {
        return new ConfigValueSet(pid, Map.of());
    }

    @Override
    public UpdateResult updateConfig(String pid, Map<String, Object> properties) {
        return new UpdateResult(null, null);
    }

    @Override
    public SnapshotResult takeSnapshot(String reason) {
        return new SnapshotResult(System.currentTimeMillis(), null);
    }

    @Override
    public RollbackResult rollback(long snapshotId) {
        return new RollbackResult(null);
    }
}
