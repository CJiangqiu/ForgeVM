package forgevm.jvm;

import java.util.List;

/**
 * Filter for Java agent attachment attempts.
 *
 * <p>Matching is performed against the agent's library path (the first
 * argument passed to {@code VirtualMachine.loadAgent} / {@code loadAgentPath}).
 * Patterns use glob syntax: {@code *} matches any sequence, {@code ?} matches a single char.
 *
 * <pre>{@code
 * // block only agents whose path contains "cheat-agent":
 * ForgeVM.banJavaAgent(AgentFilter.Blacklist("*cheat-agent*"));
 *
 * // allow only monitoring agents, block everything else:
 * ForgeVM.banJavaAgent(AgentFilter.Whitelist("*monitoring-*"));
 *
 * // multiple patterns:
 * ForgeVM.banJavaAgent(AgentFilter.Blacklist("*evil*", "*trojan*.jar"));
 * }</pre>
 */
public final class AgentFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<String> patterns;

    private AgentFilter(Mode mode, List<String> patterns) {
        this.mode = mode;
        this.patterns = patterns;
    }

    /** Block agents matching any of the given patterns. Allow everything else. */
    public static AgentFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only agents matching any of the given patterns. Block everything else. */
    public static AgentFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public Mode mode() { return mode; }
    public List<String> patterns() { return patterns; }

    private static AgentFilter build(Mode mode, String[] patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("patterns must not be empty");
        }
        for (String p : patterns) {
            if (p == null || p.isBlank()) {
                throw new IllegalArgumentException("pattern must not be null or blank");
            }
        }
        return new AgentFilter(mode, List.of(patterns));
    }
}
