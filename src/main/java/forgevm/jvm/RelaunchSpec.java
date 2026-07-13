package forgevm.jvm;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/**
 * Immutable policy for a controlled ForgeVM JVM relaunch.
 *
 * <p>The policy is sent to the out-of-process ForgeVM supervisor, which owns
 * the launch baseline and constructs the replacement process. Trusted agents
 * are inserted after inherited agent options have been removed; they are not
 * evaluated by the ordinary {@link AgentFilter}/{@link NativeFilter} rules.</p>
 */
public final class RelaunchSpec {
    public enum ExistingAgentPolicy {
        /** Remove every inherited -javaagent, -agentpath and -agentlib option. */
        DROP_ALL,
        /** Apply the supplied launch filters to inherited agent options. */
        FILTER,
        /** Compatibility mode: retain inherited agent options. */
        PRESERVE
    }

    public enum HandoffPoint {
        /** Compatibility mode: commit after the replacement process starts. */
        PROCESS_STARTED,
        /** Commit only after the trusted Java bootstrap reports policy applied. */
        POLICY_APPLIED
    }

    /** A supervisor-verified agent inserted into the replacement command line. */
    public record TrustedAgent(Path path, String sha256, String options) {
        public TrustedAgent {
            Objects.requireNonNull(path, "path");
            path = path.toAbsolutePath().normalize();
            sha256 = normalizeSha256(sha256);
            options = options == null ? "" : options;
            if (options.indexOf('\r') >= 0 || options.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("agent options must be a single line");
            }
        }
    }

    private final ExistingAgentPolicy existingAgentPolicy;
    private final TrustedAgent trustedNativeAgent;
    private final TrustedAgent trustedJavaAgent;
    private final AgentFilter agentFilter;
    private final NativeFilter nativeFilter;
    private final JvmtiFilter jvmtiFilter;
    private final ProcessFilter processFilter;
    private final boolean sanitizeEnvironment;
    private final boolean rejectArgumentFiles;
    private final HandoffPoint handoffPoint;
    private final Duration handoffTimeout;

    private RelaunchSpec(Builder builder) {
        existingAgentPolicy = builder.existingAgentPolicy;
        trustedNativeAgent = builder.trustedNativeAgent;
        trustedJavaAgent = builder.trustedJavaAgent;
        agentFilter = builder.agentFilter;
        nativeFilter = builder.nativeFilter;
        jvmtiFilter = builder.jvmtiFilter;
        processFilter = builder.processFilter;
        sanitizeEnvironment = builder.sanitizeEnvironment;
        rejectArgumentFiles = builder.rejectArgumentFiles;
        handoffPoint = builder.handoffPoint;
        handoffTimeout = builder.handoffTimeout;

        if (existingAgentPolicy == ExistingAgentPolicy.FILTER
                && agentFilter == null && nativeFilter == null) {
            throw new IllegalStateException("FILTER requires an agentFilter or nativeFilter");
        }
        if (handoffPoint == HandoffPoint.POLICY_APPLIED && trustedJavaAgent == null) {
            throw new IllegalStateException("POLICY_APPLIED requires a trusted Java agent");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public ExistingAgentPolicy existingAgentPolicy() { return existingAgentPolicy; }
    public TrustedAgent trustedNativeAgent() { return trustedNativeAgent; }
    public TrustedAgent trustedJavaAgent() { return trustedJavaAgent; }
    public AgentFilter agentFilter() { return agentFilter; }
    public NativeFilter nativeFilter() { return nativeFilter; }
    public JvmtiFilter jvmtiFilter() { return jvmtiFilter; }
    public ProcessFilter processFilter() { return processFilter; }
    public boolean sanitizeEnvironment() { return sanitizeEnvironment; }
    public boolean rejectArgumentFiles() { return rejectArgumentFiles; }
    public HandoffPoint handoffPoint() { return handoffPoint; }
    public Duration handoffTimeout() { return handoffTimeout; }

    public static final class Builder {
        private ExistingAgentPolicy existingAgentPolicy = ExistingAgentPolicy.DROP_ALL;
        private TrustedAgent trustedNativeAgent;
        private TrustedAgent trustedJavaAgent;
        private AgentFilter agentFilter;
        private NativeFilter nativeFilter;
        private JvmtiFilter jvmtiFilter;
        private ProcessFilter processFilter;
        private boolean sanitizeEnvironment = true;
        private boolean rejectArgumentFiles = true;
        private HandoffPoint handoffPoint = HandoffPoint.POLICY_APPLIED;
        private Duration handoffTimeout = Duration.ofSeconds(30);

        private Builder() {
        }

        public Builder existingAgents(ExistingAgentPolicy value) {
            existingAgentPolicy = Objects.requireNonNull(value, "value");
            return this;
        }

        public Builder trustedNativeAgent(Path path, String sha256, String options) {
            trustedNativeAgent = new TrustedAgent(path, sha256, options);
            return this;
        }

        public Builder trustedJavaAgent(Path path, String sha256, String options) {
            trustedJavaAgent = new TrustedAgent(path, sha256, options);
            return this;
        }

        public Builder agentFilter(AgentFilter value) { agentFilter = value; return this; }
        public Builder nativeFilter(NativeFilter value) { nativeFilter = value; return this; }
        public Builder jvmtiFilter(JvmtiFilter value) { jvmtiFilter = value; return this; }
        public Builder processFilter(ProcessFilter value) { processFilter = value; return this; }
        public Builder sanitizeEnvironment(boolean value) { sanitizeEnvironment = value; return this; }
        public Builder rejectArgumentFiles(boolean value) { rejectArgumentFiles = value; return this; }

        public Builder handoff(HandoffPoint point, Duration timeout) {
            handoffPoint = Objects.requireNonNull(point, "point");
            handoffTimeout = Objects.requireNonNull(timeout, "timeout");
            if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofMinutes(5)) > 0) {
                throw new IllegalArgumentException("handoff timeout must be in (0, 5 minutes]");
            }
            return this;
        }

        public RelaunchSpec build() {
            return new RelaunchSpec(this);
        }
    }

    private static String normalizeSha256(String value) {
        Objects.requireNonNull(value, "sha256");
        String normalized = value.replace(" ", "").toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("sha256 must contain exactly 64 hexadecimal characters");
        }
        return normalized;
    }
}
