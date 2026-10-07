package org.eclipse.kura.management.agent.model;

public record ConfigDescriptor(String pid, String factoryPid) {

    public boolean isFactoryConfigured() {
        return this.factoryPid != null && !this.factoryPid.isBlank();
    }
}
