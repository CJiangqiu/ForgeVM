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
 * <pre>{@code
 * // block any process whose path contains "processproxy":
 * ForgeVM.banProcessCreate(ProcessFilter.Blacklist("*processproxy*"));
 *
 * // allow only java and javaw, block everything else:
 * ForgeVM.banProcessCreate(ProcessFilter.Whitelist("*\\java.exe", "*\\javaw.exe"));
 *
 * // multiple patterns:
 * ForgeVM.banProcessCreate(ProcessFilter.Blacklist("*cheat*", "*inject*"));
 * }</pre>
 */
public final class ProcessFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<String> patterns;

    private ProcessFilter(Mode mode, List<String> patterns) {
        this.mode = mode;
        this.patterns = patterns;
    }

    /** Block processes whose image path matches any of the given patterns. Allow everything else. */
    public static ProcessFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only processes whose image path matches any of the given patterns. Block everything else. */
    public static ProcessFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public Mode mode() { return mode; }
    public List<String> patterns() { return patterns; }

    private static ProcessFilter build(Mode mode, String[] patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("patterns must not be empty");
        }
        for (String p : patterns) {
            if (p == null || p.isBlank()) {
                throw new IllegalArgumentException("pattern must not be null or blank");
            }
        }
        return new ProcessFilter(mode, List.of(patterns));
    }
}
