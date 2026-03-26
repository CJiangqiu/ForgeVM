package forgevm.jvm;

public class AgentFilter {

    public enum Mode { BLOCK_ALL, BLACKLIST, WHITELIST }

    public enum Target { CLASS, JAR }

    /** Sentinel instance for blocking all agents. */
    static final AgentFilter BLOCK_ALL_INSTANCE = new AgentFilter(Mode.BLOCK_ALL, Target.CLASS);

    private final Mode mode;
    private final Target target;
    private final String[] patterns;

    private AgentFilter(Mode mode, Target target, String... patterns) {
        this.mode = mode;
        this.target = target;
        this.patterns = patterns != null ? patterns : new String[0];
    }

    public static AgentFilter Blacklist(String... packagePrefixes) {
        if (packagePrefixes == null || packagePrefixes.length == 0) {
            throw new IllegalArgumentException("Blacklist requires at least one package prefix");
        }
        return new AgentFilter(Mode.BLACKLIST, Target.CLASS, packagePrefixes);
    }

    public static AgentFilter Whitelist(String... packagePrefixes) {
        if (packagePrefixes == null || packagePrefixes.length == 0) {
            throw new IllegalArgumentException("Whitelist requires at least one package prefix");
        }
        return new AgentFilter(Mode.WHITELIST, Target.CLASS, packagePrefixes);
    }

    public static AgentFilter JarBlacklist(String... jarGlobs) {
        if (jarGlobs == null || jarGlobs.length == 0) {
            throw new IllegalArgumentException("JarBlacklist requires at least one glob pattern");
        }
        return new AgentFilter(Mode.BLACKLIST, Target.JAR, jarGlobs);
    }

    public static AgentFilter JarWhitelist(String... jarGlobs) {
        if (jarGlobs == null || jarGlobs.length == 0) {
            throw new IllegalArgumentException("JarWhitelist requires at least one glob pattern");
        }
        return new AgentFilter(Mode.WHITELIST, Target.JAR, jarGlobs);
    }

    public Mode mode() {
        return mode;
    }

    public Target target() {
        return target;
    }

    public String[] patterns() {
        return patterns;
    }
}
