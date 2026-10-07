package org.eclipse.kura.management.agent.firewall;

import org.eclipse.kura.management.agent.model.FirewallConfig;
import org.eclipse.kura.management.agent.model.FirewallStatus;
import org.eclipse.kura.management.agent.model.FirewallUpdateRequest;
import org.eclipse.kura.management.agent.model.UpdateResult;

public interface FirewallAdapter {
    FirewallStatus getFirewallStatus();
    FirewallConfig getFirewallConfig();
    UpdateResult updateFirewallConfig(FirewallUpdateRequest request);
}
