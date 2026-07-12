package forgevm.jvm;

import java.util.List;

/**
 * Filter for native modules requesting a JVMTI environment from the target VM.
 * Matching uses a case-insensitive full-path glob against the native module
 * containing the {@code JavaVM::GetEnv} call site.
 */
public final class JvmtiFilter {
    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<String> patterns;

    private JvmtiFilter(Mode mode, List<String> patterns) {
        this.mode = mode;
        this.patterns = patterns;
    }

    /** Block callers whose module path matches any pattern. */
    public static JvmtiFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only callers whose module path matches any pattern. */
    public static JvmtiFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public Mode mode() { return mode; }
    public List<String> patterns() { return patterns; }

    private static JvmtiFilter build(Mode mode, String[] patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("patterns must not be empty");
        }
        for (String p : patterns) {
            if (p == null || p.isBlank()) {
                throw new IllegalArgumentException("pattern must not be null or blank");
            }
        }
        return new JvmtiFilter(mode, List.of(patterns));
    }
}
