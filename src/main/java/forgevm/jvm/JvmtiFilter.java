package forgevm.jvm;

import java.util.List;

/**
 * Filter for native modules requesting a JVMTI environment from the target VM.
 * Matching uses a case-insensitive full-path glob against the native module
 * containing the {@code JavaVM::GetEnv} call site.
 * Explicit source selectors use {@code module:<full-path>}; the name dimension
 * is the intercepted interface name {@code jvmti}. Legacy string patterns keep
 * their original source-module meaning.
 */
public final class JvmtiFilter {
    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<InterceptionRule> rules;

    private JvmtiFilter(Mode mode, List<InterceptionRule> rules) {
        this.mode = mode;
        this.rules = rules;
    }

    /** Block callers whose module path matches any pattern. */
    public static JvmtiFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only callers whose module path matches any pattern. */
    public static JvmtiFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public static JvmtiFilter Blacklist(InterceptionRule first, InterceptionRule... rest) {
        return new JvmtiFilter(Mode.BLACKLIST, FilterRuleSupport.explicit(first, rest));
    }

    public static JvmtiFilter Whitelist(InterceptionRule first, InterceptionRule... rest) {
        return new JvmtiFilter(Mode.WHITELIST, FilterRuleSupport.explicit(first, rest));
    }

    public Mode mode() { return mode; }
    public List<InterceptionRule> rules() { return rules; }
    public List<String> patterns() { return FilterRuleSupport.legacyPatterns(rules); }

    private static JvmtiFilter build(Mode mode, String[] patterns) {
        return new JvmtiFilter(mode, FilterRuleSupport.sources(patterns));
    }
}
