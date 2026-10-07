package org.eclipse.kura.management.agent.network;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.kura.management.agent.model.NetworkAddress;
import org.eclipse.kura.management.agent.model.NetworkConfig;
import org.eclipse.kura.management.agent.model.NetworkInterfaceInfo;
import org.eclipse.kura.management.agent.model.NetworkRoute;

public class KuraNetworkAdapter implements NetworkAdapter {

    private static final Path RESOLV_CONF = Path.of("/etc/resolv.conf");

    @Override
    public NetworkConfig getNetworkConfig() {
        List<String> errors = new ArrayList<>();
        List<NetworkInterfaceInfo> interfaces = readInterfaces(errors);
        CommandResult routesResult = runCommand(Duration.ofSeconds(2), "ip", "-o", "route", "show");
        List<NetworkRoute> routes = parseRoutes(routesResult.output());
        if (routesResult.exitCode() != 0) {
            errors.add("Unable to read routing table");
        }
        List<String> dnsServers = readDnsServers(errors);
        return new NetworkConfig(
                System.currentTimeMillis(),
                hostname(),
                interfaces,
                routes,
                dnsServers,
                "java.net.NetworkInterface, ip route, /etc/resolv.conf",
                String.join("; ", errors));
    }

    private List<NetworkInterfaceInfo> readInterfaces(List<String> errors) {
        try {
            List<NetworkInterfaceInfo> result = new ArrayList<>();
            for (NetworkInterface item : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                result.add(new NetworkInterfaceInfo(
                        item.getName(),
                        item.getDisplayName(),
                        macAddress(item),
                        item.isUp(),
                        item.isLoopback(),
                        item.isVirtual(),
                        item.isPointToPoint(),
                        item.getMTU(),
                        addresses(item)));
            }
            return result.stream()
                    .sorted((left, right) -> left.name().compareToIgnoreCase(right.name()))
                    .toList();
        } catch (SocketException e) {
            errors.add("Unable to read network interfaces");
            return List.of();
        }
    }

    private List<NetworkAddress> addresses(NetworkInterface item) {
        List<NetworkAddress> result = new ArrayList<>();
        for (InterfaceAddress address : item.getInterfaceAddresses()) {
            InetAddress inetAddress = address.getAddress();
            if (inetAddress == null) {
                continue;
            }
            String family = inetAddress instanceof Inet4Address ? "ipv4" : inetAddress instanceof Inet6Address ? "ipv6" : "unknown";
            String scope = inetAddress.isLoopbackAddress() ? "loopback"
                    : inetAddress.isLinkLocalAddress() ? "link-local"
                    : inetAddress.isSiteLocalAddress() ? "site-local"
                    : "global";
            String value = inetAddress.getHostAddress();
            short prefix = address.getNetworkPrefixLength();
            result.add(new NetworkAddress(prefix >= 0 ? value + "/" + prefix : value, family, scope));
        }
        return result;
    }

    private String macAddress(NetworkInterface item) {
        try {
            byte[] hardwareAddress = item.getHardwareAddress();
            if (hardwareAddress == null || hardwareAddress.length == 0) {
                return "";
            }
            List<String> parts = new ArrayList<>();
            for (byte value : hardwareAddress) {
                parts.add("%02x".formatted(value));
            }
            return String.join(":", parts);
        } catch (SocketException e) {
            return "";
        }
    }

    private List<NetworkRoute> parseRoutes(String output) {
        if (output == null || output.isBlank()) {
            return List.of();
        }
        return output.lines()
                .map(this::parseRoute)
                .toList();
    }

    private NetworkRoute parseRoute(String raw) {
        String[] parts = raw.trim().split("\\s+");
        String destination = parts.length > 0 ? parts[0] : "";
        String gateway = valueAfter(parts, "via");
        String device = valueAfter(parts, "dev");
        String protocol = valueAfter(parts, "proto");
        String scope = valueAfter(parts, "scope");
        String source = valueAfter(parts, "src");
        return new NetworkRoute(destination, gateway, device, protocol, scope, source, raw);
    }

    private String valueAfter(String[] parts, String key) {
        for (int i = 0; i < parts.length - 1; i += 1) {
            if (key.equals(parts[i])) {
                return parts[i + 1];
            }
        }
        return "";
    }

    private List<String> readDnsServers(List<String> errors) {
        try {
            if (!Files.exists(RESOLV_CONF)) {
                return List.of();
            }
            return Files.readString(RESOLV_CONF).lines()
                    .map(String::trim)
                    .filter(line -> line.startsWith("nameserver "))
                    .map(line -> line.substring("nameserver ".length()).trim())
                    .filter(value -> !value.isBlank())
                    .distinct()
                    .toList();
        } catch (IOException e) {
            errors.add("Unable to read DNS resolver configuration");
            return List.of();
        }
    }

    private String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "unknown";
        }
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
            return new CommandResult(process.exitValue(), new String(process.getInputStream().readAllBytes()).trim());
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
