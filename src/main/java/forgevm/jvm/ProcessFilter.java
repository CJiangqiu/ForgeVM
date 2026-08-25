package forgevm.jvm;

import java.util.List;

/**
 * Filter for process creation attempts.
 *
 * <p>Matching is performed against the image path of the process being created
 * (NT path with leading {@code \??\} stripped where present).
 * Patterns are matched case-insensitively with {@code *} as a prefix/suffix
 * wildcard: no leading {@code *} anchors the beginning and no trailing
 * {@code *} anchors the end. Unsupported internal
 * wildcards fail closed in the native guard instead of being silently ignored.
 *
 * <p>Explicit source selectors match the first non-bootstrap Java caller as
 * {@code class:...}, {@code module:...}, or {@code code:...}. A rule containing
 * both selectors requires both the child command and caller source to match.</p>
 */
public final class ProcessFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<InterceptionRule> rules;

    private ProcessFilter(Mode mode, List<InterceptionRule> rules) {
        this.mode = mode;
        this.rules = rules;
    }

    /** Block processes whose image path matches any of the given patterns. Allow everything else. */
    public static ProcessFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only processes whose image path matches any of the given patterns. Block everything else. */
    public static ProcessFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public static ProcessFilter Blacklist(InterceptionRule first, InterceptionRule... rest) {
        return new ProcessFilter(Mode.BLACKLIST, FilterRuleSupport.explicit(first, rest));
    }

    public static ProcessFilter Whitelist(InterceptionRule first, InterceptionRule... rest) {
        return new ProcessFilter(Mode.WHITELIST, FilterRuleSupport.explicit(first, rest));
    }

    public Mode mode() { return mode; }
    public List<InterceptionRule> rules() { return rules; }
    public List<String> patterns() { return FilterRuleSupport.legacyPatterns(rules); }

    private static ProcessFilter build(Mode mode, String[] patterns) {
        return new ProcessFilter(mode, FilterRuleSupport.names(patterns));
    }
}
