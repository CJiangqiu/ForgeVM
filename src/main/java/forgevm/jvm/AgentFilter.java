package forgevm.jvm;

import java.util.List;

/**
 * Filter for Java agent attachment attempts.
 *
 * <p>Matching is performed against the agent's library path (the first
 * argument passed to {@code VirtualMachine.loadAgent} / {@code loadAgentPath}).
 * Patterns are matched case-insensitively with {@code *} as a prefix/suffix
 * wildcard: no leading {@code *} anchors the beginning and no trailing
 * {@code *} anchors the end. Unsupported internal
 * wildcards fail closed in the native guard instead of being silently ignored.
 *
 * <pre>{@code
 * // block only agents whose path contains "cheat-agent":
 * ForgeVM.banJavaAgent(AgentFilter.Blacklist("*cheat-agent*"));
 *
 * // allow only monitoring agents, block everything else:
 * ForgeVM.banJavaAgent(AgentFilter.Whitelist("*monitoring-*"));
 *
 * // multiple patterns:
 * ForgeVM.banJavaAgent(AgentFilter.Blacklist("*evil*", "*trojan*"));
 * }</pre>
 *
 * <p>This filter intentionally supports agent path/name matching only. The
 * Windows attach entry does not expose an authenticated creator or source JAR
 * identity, so ForgeVM does not publish a source-rule overload for agents.</p>
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
        return new AgentFilter(mode, FilterRuleSupport.patterns(patterns));
    }
}
