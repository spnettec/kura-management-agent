package org.eclipse.kura.management.agent.system;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.kura.management.agent.model.ResourceUsage;
import org.eclipse.kura.management.agent.model.SystemInfo;

public class KuraSystemAdapter implements SystemAdapter {

    @Override
    public SystemInfo getSystemInfo() {
        return new SystemInfo(
                hostname(),
                System.getProperty("os.name", "unknown"),
                System.getProperty("os.version", "unknown"),
                System.getProperty("os.arch", "unknown"),
                detectKuraVersion(),
                System.getProperty("java.version", "unknown"),
                ManagementFactory.getRuntimeMXBean().getUptime() / 1000,
                ipAddresses());
    }

    @Override
    public ResourceUsage getResourceUsage() {
        return new ResourceUsage(cpuPct(), memoryPct(), diskPct());
    }

    @Override
    public Map<String, String> getServiceStates() {
        return Map.of(
                "kura", systemdStatus("kura"),
                "firewall", systemdStatus("firewall"),
                "cloud", "unknown");
    }

    private String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "unknown";
        }
    }

    private List<String> ipAddresses() {
        try {
            return Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                    .flatMap(networkInterface -> Collections.list(networkInterface.getInetAddresses()).stream())
                    .filter(address -> !address.isLoopbackAddress())
                    .map(InetAddress::getHostAddress)
                    .sorted()
                    .toList();
        } catch (SocketException e) {
            return List.of();
        }
    }

    private double cpuPct() {
        java.lang.management.OperatingSystemMXBean bean = ManagementFactory.getOperatingSystemMXBean();
        if (bean instanceof com.sun.management.OperatingSystemMXBean osBean) {
            double load = osBean.getSystemCpuLoad();
            return pct(load);
        }
        return 0.0;
    }

    private double memoryPct() {
        java.lang.management.OperatingSystemMXBean bean = ManagementFactory.getOperatingSystemMXBean();
        if (bean instanceof com.sun.management.OperatingSystemMXBean osBean) {
            long total = osBean.getTotalPhysicalMemorySize();
            long free = osBean.getFreePhysicalMemorySize();
            if (total > 0) {
                return pct((double) (total - free) / total);
            }
        }
        return 0.0;
    }

    private double diskPct() {
        File root = new File("/");
        long total = root.getTotalSpace();
        long free = root.getFreeSpace();
        if (total <= 0) {
            return 0.0;
        }
        return pct((double) (total - free) / total);
    }

    private double pct(double ratio) {
        if (Double.isNaN(ratio) || ratio < 0) {
            return 0.0;
        }
        return Math.round(Math.min(ratio, 1.0) * 10_000.0) / 100.0;
    }

    private String detectKuraVersion() {
        String configuredVersion = System.getProperty("kura.version");
        if (configuredVersion != null && !configuredVersion.isBlank()) {
            return configuredVersion;
        }

        CommandResult dpkgVersion = runCommand(Duration.ofSeconds(2),
                "dpkg-query", "-W", "-f=${Version}", "kura-core");
        if (dpkgVersion.exitCode() == 0 && !dpkgVersion.output().isBlank()) {
            return dpkgVersion.output();
        }

        File kuraHome = new File("/opt/eclipse/kura");
        if (kuraHome.exists()) {
            return "installed";
        }
        return "unknown";
    }

    private String systemdStatus(String serviceName) {
        CommandResult result = runCommand(Duration.ofSeconds(2), "systemctl", "is-active", serviceName);
        if (result.exitCode() == 0 && !result.output().isBlank()) {
            return result.output();
        }
        if ("inactive".equals(result.output()) || "failed".equals(result.output())) {
            return result.output();
        }
        return "unknown";
    }

    private CommandResult runCommand(Duration timeout, String... command) {
        Process process = null;
        try {
            process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            boolean completed = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!completed) {
                process.destroyForcibly();
                return new CommandResult(-1, "");
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            return new CommandResult(process.exitValue(), output);
        } catch (IOException e) {
            return new CommandResult(-1, "");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return new CommandResult(-1, "");
        }
    }

    private record CommandResult(int exitCode, String output) {
    }
}
