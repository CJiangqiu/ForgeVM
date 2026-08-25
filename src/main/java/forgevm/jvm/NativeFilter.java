package forgevm.jvm;

import java.util.List;

/**
 * Filter for native library loading attempts.
 *
 * <p>Matching is performed against the library path passed to
 * {@code System.load} / {@code System.loadLibrary} / {@code Runtime.load*}.
 * Patterns are matched case-insensitively with {@code *} as a prefix/suffix
 * wildcard: no leading {@code *} anchors the beginning and no trailing
 * {@code *} anchors the end. Unsupported internal
 * wildcards fail closed in the native guard instead of being silently ignored.
 *
 * <pre>{@code
 * // block any DLL whose path contains "cheat":
 * ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*"));
 *
 * // allow only lwjgl natives, block everything else:
 * ForgeVM.banNativeLoad(NativeFilter.Whitelist("*lwjgl*", "*trusted-native*"));
 *
 * // multiple patterns:
 * ForgeVM.banNativeLoad(NativeFilter.Blacklist("*hack*", "*inject*"));
 * }</pre>
 *
 * <p>Explicit source selectors match the first non-bootstrap Java caller as
 * {@code class:...}, {@code module:...}, or {@code code:...}. A rule containing
 * both selectors requires both the library name/path and caller source to
 * match.</p>
 */
public final class NativeFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<InterceptionRule> rules;

    private NativeFilter(Mode mode, List<InterceptionRule> rules) {
        this.mode = mode;
        this.rules = rules;
    }

    /** Block libraries matching any of the given patterns. Allow everything else. */
    public static NativeFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only libraries matching any of the given patterns. Block everything else. */
    public static NativeFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public static NativeFilter Blacklist(InterceptionRule first, InterceptionRule... rest) {
        return new NativeFilter(Mode.BLACKLIST, FilterRuleSupport.explicit(first, rest));
    }

    public static NativeFilter Whitelist(InterceptionRule first, InterceptionRule... rest) {
        return new NativeFilter(Mode.WHITELIST, FilterRuleSupport.explicit(first, rest));
    }

    public Mode mode() { return mode; }
    public List<InterceptionRule> rules() { return rules; }
    public List<String> patterns() { return FilterRuleSupport.legacyPatterns(rules); }

    private static NativeFilter build(Mode mode, String[] patterns) {
        return new NativeFilter(mode, FilterRuleSupport.names(patterns));
    }
}
