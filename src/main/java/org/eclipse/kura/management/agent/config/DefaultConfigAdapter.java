package org.eclipse.kura.management.agent.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.kura.management.agent.model.ConfigDescriptor;
import org.eclipse.kura.management.agent.model.RollbackResult;
import org.eclipse.kura.management.agent.model.SnapshotResult;

import com.fasterxml.jackson.databind.JsonNode;

public class DefaultConfigAdapter implements ConfigAdapter {

    private final KuraRestClient rest;

    public DefaultConfigAdapter(KuraRestClient rest) {
        this.rest = rest;
    }

    @Override
    public List<ConfigDescriptor> listConfigs() {
        JsonNode root = this.rest.get("/configuration/v2/configurableComponents/pidsWithFactory");
        List<ConfigDescriptor> result = new ArrayList<>();
        for (JsonNode component : root.path("components")) {
            String factoryPid = component.path("factoryPid").asText(null);
            result.add(new ConfigDescriptor(component.path("pid").asText(), factoryPid));
        }
        return result;
    }

    @Override
    public JsonNode getConfig(String pid) {
        return this.rest.post("/configuration/v2/configurableComponents/configurations/byPid",
                Map.of("pids", List.of(pid)));
    }

    @Override
    public JsonNode updateConfig(String pid, Object configuration) {
        // The REST contract (UpdateComponentConfigurationRequest) expects a "configs" array
        // of ComponentConfiguration entries that are passed through untouched.
        return this.rest.put("/configuration/v2/configurableComponents/configurations/_update",
                Map.of("configs", List.of(configuration)));
    }

    @Override
    public SnapshotResult takeSnapshot() {
        JsonNode result = this.rest.post("/configuration/v2/snapshots/_write", Map.of());
        return new SnapshotResult(result.path("id").asLong());
    }

    @Override
    public List<Long> listSnapshots() {
        JsonNode root = this.rest.get("/configuration/v2/snapshots");
        List<Long> ids = new ArrayList<>();
        for (JsonNode id : root.path("ids")) {
            ids.add(id.asLong());
        }
        return ids;
    }

    @Override
    public RollbackResult rollback(Long snapshotId) {
        JsonNode result;
        if (snapshotId == null) {
            result = this.rest.post("/configuration/v2/snapshots/_rollback", Map.of());
        } else {
            result = this.rest.post("/configuration/v2/snapshots/byId/_rollback", Map.of("id", snapshotId));
        }
        return new RollbackResult(result.path("id").asLong());
    }
}
