package org.eclipse.kura.management.agent.firewall;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.kura.management.agent.model.FirewallConfig;
import org.eclipse.kura.management.agent.model.FirewallRuleSet;
import org.eclipse.kura.management.agent.model.FirewallStatus;
import org.eclipse.kura.management.agent.model.FirewallUpdateRequest;
import org.eclipse.kura.management.agent.model.UpdateResult;

public class KuraFirewallAdapter implements FirewallAdapter {

    private static final Path IPV4_RULES = Path.of("/etc/sysconfig/iptables");
    private static final Path IPV6_RULES = Path.of("/etc/sysconfig/ip6tables");
    private static final Path KURA_PROPERTIES = Path.of("/opt/eclipse/kura/framework/kura.properties");
    private final IptablesSaveParser parser = new IptablesSaveParser();

    @Override
    public FirewallStatus getFirewallStatus() {
        FirewallSnapshot snapshot = collectSnapshot(false);
        return new FirewallStatus(
                snapshot.enabled(),
                snapshot.running(),
                snapshot.healthy(),
                snapshot.packageInstalled(),
                snapshot.serviceState(),
                snapshot.systemdState(),
                snapshot.healthMessage(),
                countRules(snapshot.parsedRules().get(0)),
                countRules(snapshot.parsedRules().get(1)),
                snapshot.collectedAt(),
                snapshot.source(),
                snapshot.errorMessage());
    }

    @Override
    public FirewallConfig getFirewallConfig() {
        FirewallSnapshot snapshot = collectSnapshot(true);
        return new FirewallConfig(
                snapshot.enabled(),
                snapshot.running(),
                snapshot.healthy(),
                snapshot.packageInstalled(),
                snapshot.serviceState(),
                snapshot.systemdState(),
                snapshot.healthMessage(),
                snapshot.collectedAt(),
                snapshot.source(),
                snapshot.errorMessage(),
                snapshot.ipv4Rules(),
                snapshot.ipv6Rules(),
                snapshot.parsedRules(),
                List.of());
    }

    @Override
    public UpdateResult updateFirewallConfig(FirewallUpdateRequest request) {
        return new UpdateResult(null, null);
    }

    private FirewallSnapshot collectSnapshot(boolean includeRawRules) {
        long collectedAt = System.currentTimeMillis();
        boolean installed = isPackageInstalled() || Files.exists(Path.of("/opt/eclipse/kura/siblings/firewall"));
        boolean adminEnabled = isFirewallAdminEnabled();
        String systemdState = systemdStatus("firewall");
        RuleContent ipv4 = readRules("ipv4", IPV4_RULES, "iptables-save", includeRawRules);
        RuleContent ipv6 = readRules("ipv6", IPV6_RULES, "ip6tables-save", includeRawRules);
        FirewallRuleSet ipv4Parsed = parser.parse("ipv4", ipv4.content());
        FirewallRuleSet ipv6Parsed = parser.parse("ipv6", ipv6.content());
        String source = "ipv4=%s,ipv6=%s".formatted(ipv4.source(), ipv6.source());
        String errorMessage = joinErrors(ipv4.errorMessage(), ipv6.errorMessage());
        int ipv4RuleCount = countRules(ipv4Parsed);
        int ipv6RuleCount = countRules(ipv6Parsed);
        boolean hasRules = ipv4RuleCount > 0 || ipv6RuleCount > 0;
        boolean enabled = adminEnabled || hasRules;
        boolean running = enabled && hasRules;
        boolean healthy = adminEnabled && hasRules && errorMessage.isBlank();
        String serviceState = adminEnabled ? "enabled" : "disabled";
        String healthMessage = healthMessage(adminEnabled, hasRules, errorMessage);

        return new FirewallSnapshot(
                enabled,
                running,
                healthy,
                installed,
                serviceState,
                systemdState,
                healthMessage,
                collectedAt,
                source,
                errorMessage,
                includeRawRules ? ipv4.content() : "",
                includeRawRules ? ipv6.content() : "",
                List.of(ipv4Parsed, ipv6Parsed));
    }

    private RuleContent readRules(String ipVersion, Path fallbackFile, String command, boolean includeRawRules) {
        CommandResult live = runCommand(Duration.ofSeconds(3), command);
        if (live.exitCode() == 0 && !live.output().isBlank()) {
            return new RuleContent(includeRawRules ? live.output() : live.output(), command, "");
        }

        String fallback = readFile(fallbackFile);
        if (!fallback.isBlank()) {
            return new RuleContent(includeRawRules ? fallback : fallback, fallbackFile.toString(), "");
        }

        String message = live.exitCode() == 0
                ? ""
                : "%s unavailable for %s".formatted(command, ipVersion);
        return new RuleContent("", "none", message);
    }

    private int countRules(FirewallRuleSet ruleSet) {
        return ruleSet.tables().stream()
                .mapToInt(table -> table.rules().size())
                .sum();
    }

    private String joinErrors(String... messages) {
        List<String> values = new ArrayList<>();
        for (String message : messages) {
            if (message != null && !message.isBlank()) {
                values.add(message);
            }
        }
        return String.join("; ", values);
    }

    private String healthMessage(boolean adminEnabled, boolean hasRules, String errorMessage) {
        if (!adminEnabled) {
            return "Kura firewall admin is disabled";
        }
        if (!hasRules) {
            return "No active firewall rules were found";
        }
        if (!errorMessage.isBlank()) {
            return errorMessage;
        }
        return "Kura firewall is enabled and active rules are present";
    }

    private boolean isFirewallAdminEnabled() {
        try {
            if (!Files.exists(KURA_PROPERTIES)) {
                return false;
            }
            return Files.readString(KURA_PROPERTIES).lines()
                    .anyMatch(line -> line.trim().equals("kura.have.firewall.admin=true"));
        } catch (IOException e) {
            return false;
        }
    }

    private boolean isPackageInstalled() {
        return runCommand(Duration.ofSeconds(2), "dpkg-query", "-W", "kura-firewall-only").exitCode() == 0;
    }

    private String systemdStatus(String serviceName) {
        CommandResult result = runCommand(Duration.ofSeconds(2), "systemctl", "is-active", serviceName);
        if (!result.output().isBlank()) {
            return result.output();
        }
        return "unknown";
    }

    private String readFile(Path path) {
        try {
            if (!Files.exists(path)) {
                return "";
            }
            return Files.readString(path);
        } catch (IOException e) {
            return "";
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

    private record RuleContent(String content, String source, String errorMessage) {
    }

    private record FirewallSnapshot(
            boolean enabled,
            boolean running,
            boolean healthy,
            boolean packageInstalled,
            String serviceState,
            String systemdState,
            String healthMessage,
            long collectedAt,
            String source,
            String errorMessage,
            String ipv4Rules,
            String ipv6Rules,
            List<FirewallRuleSet> parsedRules) {
    }
}
