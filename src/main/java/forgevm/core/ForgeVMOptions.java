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

    private final boolean independentLifecycle;
    private final boolean statusWindow;
    private final boolean lockJvm;

    private ForgeVMOptions(Builder builder) {
        this.independentLifecycle = builder.independentLifecycle;
        this.statusWindow = builder.statusWindow;
        this.lockJvm = builder.lockJvm;
    }

    /** Default policy: no window and no independent agent lifecycle. */
    public static ForgeVMOptions defaults() {
        return DEFAULT;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Whether the agent should remain alive after its target JVM exits. */
    public boolean independentLifecycle() {
        return independentLifecycle;
    }

    /** Whether to show the ForgeVM status and command window. */
    public boolean statusWindow() {
        return statusWindow;
    }

    /** Whether unauthorized JVM termination should be recovered by the agent. */
    public boolean lockJvm() {
        return lockJvm;
    }

    public static final class Builder {
        private boolean independentLifecycle;
        private boolean statusWindow;
        private boolean lockJvm;

        private Builder() {
        }

        public Builder independentLifecycle(boolean value) {
            independentLifecycle = value;
            return this;
        }

        public Builder statusWindow(boolean value) {
            statusWindow = value;
            return this;
        }

        public Builder lockJvm(boolean value) {
            lockJvm = value;
            return this;
        }

        public ForgeVMOptions build() {
            if (lockJvm && !independentLifecycle) {
                throw new IllegalStateException(
                        "lockJvm requires independentLifecycle=true");
            }
            if (lockJvm && !statusWindow) {
                throw new IllegalStateException(
                        "lockJvm requires statusWindow=true so it can be stopped safely");
            }
            return new ForgeVMOptions(this);
        }
    }
}
