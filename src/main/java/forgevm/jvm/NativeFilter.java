package forgevm.jvm;

public class NativeFilter {

    public enum Mode { BLOCK_ALL, BLACKLIST, WHITELIST }

    /** Sentinel instance for blocking all native library loading. */
    static final NativeFilter BLOCK_ALL_INSTANCE = new NativeFilter(Mode.BLOCK_ALL);

    private final Mode mode;
    private final String[] patterns;

    private NativeFilter(Mode mode, String... patterns) {
        this.mode = mode;
        this.patterns = patterns != null ? patterns : new String[0];
    }

    /**
     * Block native libraries whose path or name matches any of the given glob patterns.
     * <p>Examples: {@code "badmod*"}, {@code "*cheat*.dll"}
     */
    public static NativeFilter Blacklist(String... globs) {
        if (globs == null || globs.length == 0) {
            throw new IllegalArgumentException("Blacklist requires at least one pattern");
        }
        return new NativeFilter(Mode.BLACKLIST, globs);
    }

    /**
     * Only allow native libraries whose path or name matches at least one of the given glob patterns.
     * All others are blocked.
     * <p>Examples: {@code "forgevm*"}, {@code "lwjgl*"}
     */
    public static NativeFilter Whitelist(String... globs) {
        if (globs == null || globs.length == 0) {
            throw new IllegalArgumentException("Whitelist requires at least one pattern");
        }
        return new NativeFilter(Mode.WHITELIST, globs);
    }

    public Mode mode() {
        return mode;
    }

    public String[] patterns() {
        return patterns;
    }
}
