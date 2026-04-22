package forgevm.jvm;

import java.util.List;

/**
 * Filter for native library loading attempts.
 *
 * <p>Matching is performed against the library path passed to
 * {@code System.load} / {@code System.loadLibrary} / {@code Runtime.load*}.
 * Patterns use glob syntax: {@code *} matches any sequence, {@code ?} matches a single char.
 *
 * <pre>{@code
 * // block any DLL whose path contains "cheat":
 * ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*"));
 *
 * // allow only lwjgl natives, block everything else:
 * ForgeVM.banNativeLoad(NativeFilter.Whitelist("lwjgl*", "*lwjgl*.dll"));
 *
 * // multiple patterns:
 * ForgeVM.banNativeLoad(NativeFilter.Blacklist("*hack*.dll", "*inject*.dll"));
 * }</pre>
 */
public final class NativeFilter {

    public enum Mode { BLACKLIST, WHITELIST }

    private final Mode mode;
    private final List<String> patterns;

    private NativeFilter(Mode mode, List<String> patterns) {
        this.mode = mode;
        this.patterns = patterns;
    }

    /** Block libraries matching any of the given patterns. Allow everything else. */
    public static NativeFilter Blacklist(String... patterns) {
        return build(Mode.BLACKLIST, patterns);
    }

    /** Allow only libraries matching any of the given patterns. Block everything else. */
    public static NativeFilter Whitelist(String... patterns) {
        return build(Mode.WHITELIST, patterns);
    }

    public Mode mode() { return mode; }
    public List<String> patterns() { return patterns; }

    private static NativeFilter build(Mode mode, String[] patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("patterns must not be empty");
        }
        for (String p : patterns) {
            if (p == null || p.isBlank()) {
                throw new IllegalArgumentException("pattern must not be null or blank");
            }
        }
        return new NativeFilter(mode, List.of(patterns));
    }
}
