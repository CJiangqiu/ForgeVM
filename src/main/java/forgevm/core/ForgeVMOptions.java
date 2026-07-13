package forgevm.core;

/**
 * Startup policy for a ForgeVM agent.
 *
 * <p>The options are consumed when ForgeVM creates its first agent process.
 * Later calls to {@link ForgeVM#launch(ForgeVMOptions)} reuse that agent and
 * therefore do not change its policy.</p>
 */
public final class ForgeVMOptions {
    private static final ForgeVMOptions DEFAULT = builder().build();

    private final boolean window;
    private final boolean lockJvm;

    private ForgeVMOptions(Builder builder) {
        this.window = builder.window;
        this.lockJvm = builder.lockJvm;
    }

    /** Default policy: no window, no JVM protection. */
    public static ForgeVMOptions defaults() {
        return DEFAULT;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Whether to show the ForgeVM live status and command window.
     * When enabled without {@link #lockJvm()}, the agent logs the JVM death
     * and exits cleanly if the JVM disappears without a relaunch handoff.
     * When {@link #lockJvm()} is active, the window is always enabled. */
    public boolean window() {
        return window || lockJvm;
    }

    /**
     * Whether the agent protects the JVM lifecycle: DACL termination lock,
     * {@code Shutdown.halt()} interception, and guard recovery (up to 4
     * consecutive attempts). Implies {@link #window()}. */
    public boolean lockJvm() {
        return lockJvm;
    }

    public static final class Builder {
        private boolean window;
        private boolean lockJvm;

        private Builder() {
        }

        /** Show the ForgeVM live status window. */
        public Builder window(boolean value) {
            window = value;
            return this;
        }

        /** Protect the JVM from termination and attempt recovery on death. */
        public Builder lockJvm(boolean value) {
            lockJvm = value;
            return this;
        }

        public ForgeVMOptions build() {
            return new ForgeVMOptions(this);
        }
    }
}
