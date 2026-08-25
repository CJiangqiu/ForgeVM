package forgevm.jvm;

import java.util.List;

/**
 * Filter for Java platform-thread creation attempts.
 *
 * <p>Matching is performed against {@link Thread#getName()} immediately before
 * HotSpot starts the native thread. Patterns are case-insensitive and support
 * {@code *} only as a prefix and/or suffix. A rejected start is silently
 * discarded: {@link Thread#start()} returns without an exception and no native
 * thread is created.</p>
 *
 * <pre>{@code
 * ForgeVM.banThreadCreate(ThreadFilter.Blacklist("*worker-flood*"));
 * ForgeVM.banThreadCreate(ThreadFilter.Whitelist("main", "fvm-*", "server-*"));
 * }</pre>
 *
 * <p>Explicit source selectors match the first non-bootstrap
 * {@link Thread#start()} caller as {@code class:...}, {@code module:...}, or
 * {@code code:...}. A rule containing both selectors requires both the thread
 * name and caller source to match.</p>
 */
public final class ThreadFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<InterceptionRule> rules;

    private ThreadFilter(Mode mode, List<InterceptionRule> rules) {
        this.mode = mode;
        this.rules = rules;
    }

    /** Block thread names matching any pattern and allow all other names. */
    public static ThreadFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only thread names matching a pattern and block every other name. */
    public static ThreadFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public static ThreadFilter Blacklist(InterceptionRule first, InterceptionRule... rest) {
        return new ThreadFilter(Mode.BLACKLIST, FilterRuleSupport.explicit(first, rest));
    }

    public static ThreadFilter Whitelist(InterceptionRule first, InterceptionRule... rest) {
        return new ThreadFilter(Mode.WHITELIST, FilterRuleSupport.explicit(first, rest));
    }

    public Mode mode() { return mode; }
    public List<InterceptionRule> rules() { return rules; }
    public List<String> patterns() { return FilterRuleSupport.legacyPatterns(rules); }

    private static ThreadFilter build(Mode mode, String[] patterns) {
        return new ThreadFilter(mode, FilterRuleSupport.names(patterns));
    }
}
