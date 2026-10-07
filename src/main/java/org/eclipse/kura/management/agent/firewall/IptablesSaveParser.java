package org.eclipse.kura.management.agent.firewall;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.kura.management.agent.model.FirewallChain;
import org.eclipse.kura.management.agent.model.FirewallRule;
import org.eclipse.kura.management.agent.model.FirewallRuleSet;
import org.eclipse.kura.management.agent.model.FirewallTable;

public class IptablesSaveParser {

    public FirewallRuleSet parse(String ipVersion, String content) {
        List<FirewallTable> tables = new ArrayList<>();
        String tableName = null;
        List<FirewallChain> chains = new ArrayList<>();
        List<FirewallRule> rules = new ArrayList<>();

        for (String rawLine : content.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("*")) {
                if (tableName != null) {
                    tables.add(new FirewallTable(tableName, List.copyOf(chains), List.copyOf(rules)));
                    chains.clear();
                    rules.clear();
                }
                tableName = line.substring(1);
                continue;
            }
            if ("COMMIT".equals(line)) {
                if (tableName != null) {
                    tables.add(new FirewallTable(tableName, List.copyOf(chains), List.copyOf(rules)));
                    tableName = null;
                    chains.clear();
                    rules.clear();
                }
                continue;
            }
            if (line.startsWith(":")) {
                chains.add(parseChain(line));
                continue;
            }
            if (line.startsWith("-A ") || line.startsWith("-I ")) {
                rules.add(parseRule(line));
            }
        }

        if (tableName != null) {
            tables.add(new FirewallTable(tableName, List.copyOf(chains), List.copyOf(rules)));
        }
        return new FirewallRuleSet(ipVersion, tables);
    }

    private FirewallChain parseChain(String line) {
        String[] parts = line.substring(1).split("\\s+", 3);
        String name = parts.length > 0 ? parts[0] : "";
        String policy = parts.length > 1 ? parts[1] : "";
        String counters = parts.length > 2 ? parts[2] : "";
        return new FirewallChain(name, policy, counters);
    }

    private FirewallRule parseRule(String line) {
        String[] parts = line.split("\\s+", 3);
        String action = parts.length > 0 ? parts[0] : "";
        String chain = parts.length > 1 ? parts[1] : "";
        String expression = parts.length > 2 ? parts[2] : "";
        return new FirewallRule(action, chain, expression);
    }
}
