package org.eclipse.kura.management.agent.system;

import java.util.Map;

import org.eclipse.kura.management.agent.model.ResourceUsage;
import org.eclipse.kura.management.agent.model.SystemInfo;

public interface SystemAdapter {
    SystemInfo getSystemInfo();
    ResourceUsage getResourceUsage();
    Map<String, String> getServiceStates();
}
