package forgevm.core;

import forgevm.jvm.AgentFilter;
import forgevm.jvm.JvmControl;
import forgevm.jvm.NativeFilter;
import forgevm.jvm.JvmtiFilter;
import forgevm.jvm.ProcessFilter;
import forgevm.jvm.RelaunchException;
import forgevm.jvm.RelaunchSpec;
import forgevm.memory.MemoryUtil;
import forgevm.forge.ForgeManager;
import forgevm.util.FvmLog;
import forgevm.util.JsonUtils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public final class ForgeVM {
    private static final String ENV_AGENT_EXE_PATH = "FORGEVM_AGENT_EXE_PATH";
    private static final String PROP_AGENT_EXE_PATH = "forgevm.agent.exe.path";
    /** Set by the persistent agent on the new JVM's command line after relaunch.
     *  Value is the agent's own PID - used to construct the handoff named pipe
     *  path. When this property is present, launch() reuses the existing agent
     *  instead of spawning a new one. */
    private static final String PROP_AGENT_HANDOFF_PID = "forgevm.agent.pid";
    /** Set by the agent on each relaunched JVM's command line: a monotonically
     *  increasing counter, incremented once per relaunch. Absence (or "0") means
     *  the current JVM has never been relaunched. Exposed via
     *  {@link #relaunchGeneration()} so callers can implement their own stop
     *  condition (a soft cap, a "clean once" guard, an adaptive halt). */
    private static final String PROP_RELAUNCH_GEN = "forgevm.relaunch.gen";
    private static final String ENV_NATIVE_DLL_PATH = "FORGEVM_NATIVE_DLL_PATH";
    private static final String PROP_NATIVE_DLL_PATH = "forgevm.native." + chars('d', 'l', 'l') + ".path";

    private static final String AGENT_EXE_FILE = "forgevm_agent.exe";
    private static final String DLL_FILE = "forgevm_native" + chars('.', 'd', 'l', 'l');
    private static final String FORGEVM_RUNTIME_DIR = "ForgeVM";
    private static final String RESOURCE_AGENT_PATH = "/forgevm/native/win-x64/forgevm_agent.exe";
    private static final String RESOURCE_DLL_PATH = "/forgevm/native/win-x64/" + DLL_FILE;
    private static final long AGENT_IO_TIMEOUT_SECONDS = 120L;

    private static volatile LaunchResult state;
    private static volatile AgentSession agentSession;
    private static volatile JvmControl.ExitCommandSender agentExitSender;
    private static volatile JvmControl.AgentLockController agentLockController;

    private static volatile MemoryUtil FIELD_MEMORY;
    private static volatile ForgeManager FORGE_MANAGER;

    /** Temporary holder for object references during putObjectField. Agent reads OOP from here. */
    @SuppressWarnings("unused") // read by Agent via RPM
    private static volatile Object __tempRef;
    private static final Object TEMP_REF_LOCK = new Object();

    /**
     * Hold a temporary object reference so the Agent can read its OOP.
     */
    public static void withTempRef(Object value, Runnable action) {
        synchronized (TEMP_REF_LOCK) {
            __tempRef = value;
            try {
                action.run();
            } finally {
                __tempRef = null;
            }
        }
    }

    private ForgeVM() {
    }

    /** Policy used when the first agent process is spawned. */
    private static volatile ForgeVMOptions launchOptions = ForgeVMOptions.defaults();

    // -- launch --

    /**
     * Launch ForgeVM with the default startup policy.
     *
     * @deprecated Use {@link #launch(ForgeVMOptions)} so lifecycle and JVM
     * protection policy are explicit.
     */
    @Deprecated(since = "0.6.10", forRemoval = false)
    public static LaunchResult launch() {
        return launch(ForgeVMOptions.defaults());
    }

    /**
     * Launch ForgeVM, optionally opening the agent's live status window — a
     * separate-process window streaming [FVM] agent activity and [JVM] target
     * health (thread/CPU sampling, spin/deadlock warnings) in real time. The
     * window lives in the persistent agent and survives relaunch automatically.
     *
     * @deprecated Use {@link #launch(ForgeVMOptions)} and set
     * {@link ForgeVMOptions.Builder#window(boolean)} instead.
     */
    @Deprecated(since = "0.6.10", forRemoval = false)
    public static LaunchResult launch(boolean withStatusWindow) {
        return launch(ForgeVMOptions.builder()
                .window(withStatusWindow)
                .build());
    }

    /**
     * Launch ForgeVM with an explicit startup policy. The policy is sent to
     * the initial agent process and remains fixed for that agent's lifetime.
     */
    public static synchronized LaunchResult launch(ForgeVMOptions options) {
        launchOptions = java.util.Objects.requireNonNull(options, "options");

        AgentSession currentSession = agentSession;
        if (currentSession != null && !currentSession.isAlive()) {
            clearAgentExitSender();
            clearAgentLockController();
            closeAgentSession(currentSession);
            agentSession = null;
        }

        if (state != null && state.nativeDllActive()
                && agentSession != null && agentSession.isAlive()) {
            return state;
        }

        LaunchResult result = launchInternal();
        state = result;
        if (result.agentStatus() == AgentStatus.UNAVAILABLE) {
            FvmLog.error("ForgeVM launch failed: " + result.reason());
        }
        return result;
    }

    public static boolean isAgentActive() {
        AgentSession session = agentSession;
        return session != null && session.isAlive();
    }

    // -- memory API --

    public static MemoryUtil memory() {
        MemoryUtil m = FIELD_MEMORY;
        if (m == null) {
            m = new MemoryUtil();
            FIELD_MEMORY = m;
        }
        return m;
    }

    // -- forge API --

    public static ForgeManager forge() {
        ForgeManager m = FORGE_MANAGER;
        if (m == null) {
            m = new ForgeManager();
            FORGE_MANAGER = m;
        }
        return m;
    }

    // -- jvm control --

    /** Kill the target JVM via out-of-process {@code TerminateProcess}. Not a wrapper for {@code System.exit}. */
    public static boolean exitJvm() {
        return JvmControl.exitJvm();
    }

    /** Kill the target JVM with the given exit code via out-of-process {@code TerminateProcess}. */
    public static boolean exitJvm(int exitCode) {
        return JvmControl.exitJvm(exitCode);
    }

    public static boolean lockAgent(int ttlSeconds) {
        return JvmControl.lockAgent(ttlSeconds);
    }

    public static boolean lockAgent() {
        return JvmControl.lockAgent();
    }

    public static boolean unlockAgent() {
        return JvmControl.unlockAgent();
    }

    // -- java agent guard (native-level, patches JVM_EnqueueOperation in jvm.dll) --

    /**
     * Comprehensive Java agent ban: purges every already-loaded agent and blocks
     * every future attach attempt. Irreversible for the purge arm.
     */
    public static boolean banJavaAgent() {
        return banJavaAgentInternal(null);
    }

    /**
     * Filtered Java agent ban: purges already-loaded agents whose source jar
     * matches {@code filter}, and blocks future attach attempts whose jar path
     * matches the same filter. Agents whose jar identity cannot be resolved
     * (boot loader, dynamically-generated classes) are NOT purged - call
     * {@link #banJavaAgent()} with no filter for unconditional purge.
     *
     * <p>The purge arm is irreversible; the future-attach block is reversible
     * via {@link #unbanJavaAgent()}.
     */
    public static boolean banJavaAgent(AgentFilter filter) {
        return banJavaAgentInternal(filter);
    }

    public static boolean unbanJavaAgent() {
        return sendFilterCommand("unban_java_agent", null, null);
    }

    private static boolean banJavaAgentInternal(AgentFilter filter) {
        String mode = filter == null ? null : filter.mode().name();
        List<String> patterns = filter == null ? null : filter.patterns();
        boolean ok = sendFilterCommand("purge_matching_agents", mode, patterns);
        ok &= sendFilterCommand("ban_java_agent", mode, patterns);
        return ok;
    }

    // -- native load guard (loader-level, patches ntdll!LdrLoadDll) --

    /** Block all native library loads (System.load / System.loadLibrary / Runtime.load*). */
    public static boolean banNativeLoad() {
        return sendFilterCommand("ban_native_load", null, null);
    }

    /** Block native library loads matching the filter. */
    public static boolean banNativeLoad(NativeFilter filter) {
        return sendFilterCommand("ban_native_load",
                filter == null ? null : filter.mode().name(),
                filter == null ? null : filter.patterns());
    }

    public static boolean unbanNativeLoad() {
        return sendFilterCommand("unban_native_load", null, null);
    }

    // -- JVMTI acquisition guard (native-level, patches JavaVM::GetEnv) --

    /** Block all requests for a JVMTI environment. */
    public static boolean banJvmti() {
        return sendFilterCommand("ban_jvmti", null, null);
    }

    /** Block JVMTI acquisition requests from native modules matching the filter. */
    public static boolean banJvmti(JvmtiFilter filter) {
        return sendFilterCommand("ban_jvmti",
                filter == null ? null : filter.mode().name(),
                filter == null ? null : filter.patterns());
    }

    /** Remove the JVMTI acquisition filter. */
    public static boolean unbanJvmti() {
        return sendFilterCommand("unban_jvmti", null, null);
    }

    // -- process create guard (loader-level, hooks ntdll!NtCreateUserProcess) --

    /** Block all child process creation. */
    public static boolean banProcessCreate() {
        return sendFilterCommand("ban_process_create", null, null);
    }

    /** Block child process creation matching the filter. */
    public static boolean banProcessCreate(ProcessFilter filter) {
        return sendFilterCommand("ban_process_create",
                filter == null ? null : filter.mode().name(),
                filter == null ? null : filter.patterns());
    }

    public static boolean unbanProcessCreate() {
        return sendFilterCommand("unban_process_create", null, null);
    }

    // -- relaunch (kill + restart JVM with filtered command line) --

    /**
     * Relaunch from the supervisor-owned launch baseline using an immutable v2
     * policy. The public operation intentionally remains named {@code relaunch};
     * the spec selects the controlled implementation rather than the legacy
     * current-command-line implementation.
     *
     * <p>On success this method never returns. If creation, verification or the
     * requested handoff fails, the original JVM remains alive and a
     * {@link RelaunchException} is thrown.</p>
     */
    public static void relaunch(RelaunchSpec spec) throws RelaunchException {
        if (spec == null) throw new IllegalArgumentException("spec must not be null");
        relaunchV2(spec);
    }

    /** Relaunch the JVM, keeping all existing -javaagent/-agentpath args. Never returns on success. */
    public static void relaunch() throws RelaunchException {
        relaunchInternal(null, null, null, null);
    }

    /** Relaunch the JVM, applying agentFilter to -javaagent: args on the new command line. Never returns on success. */
    public static void relaunch(AgentFilter agentFilter) throws RelaunchException {
        relaunchInternal(agentFilter, null, null, null);
    }

    /** Relaunch the JVM, applying nativeFilter to -agentpath: args on the new command line. Never returns on success. */
    public static void relaunch(NativeFilter nativeFilter) throws RelaunchException {
        relaunchInternal(null, nativeFilter, null, null);
    }

    /** Relaunch the JVM, applying both filters to the new command line. Never returns on success. */
    public static void relaunch(AgentFilter agentFilter, NativeFilter nativeFilter) throws RelaunchException {
        relaunchInternal(agentFilter, nativeFilter, null, null);
    }

    /**
     * Relaunch the JVM with a process creation filter pre-installed on the new JVM.
     * The filter is active from the new JVM's first instruction - no window exists
     * in which a spawned child process could escape the filter.
     * Never returns on success.
     */
    public static void relaunch(ProcessFilter processFilter) throws RelaunchException {
        relaunchInternal(null, null, null, processFilter);
    }

    /** Relaunch the JVM, applying agentFilter to -javaagent: args and pre-installing processFilter. Never returns on success. */
    public static void relaunch(AgentFilter agentFilter, ProcessFilter processFilter) throws RelaunchException {
        relaunchInternal(agentFilter, null, null, processFilter);
    }

    /** Relaunch the JVM, applying nativeFilter to -agentpath: args and pre-installing processFilter. Never returns on success. */
    public static void relaunch(NativeFilter nativeFilter, ProcessFilter processFilter) throws RelaunchException {
        relaunchInternal(null, nativeFilter, null, processFilter);
    }

    /** Relaunch the JVM, applying all three filters. Never returns on success. */
    public static void relaunch(AgentFilter agentFilter, NativeFilter nativeFilter, ProcessFilter processFilter) throws RelaunchException {
        relaunchInternal(agentFilter, nativeFilter, null, processFilter);
    }

    /** Relaunch with a JVMTI acquisition filter pre-installed once the target JVM exposes jvm.dll. */
    public static void relaunch(JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(null, null, jvmtiFilter, null);
    }

    public static void relaunch(AgentFilter agentFilter, JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(agentFilter, null, jvmtiFilter, null);
    }

    public static void relaunch(NativeFilter nativeFilter, JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(null, nativeFilter, jvmtiFilter, null);
    }

    public static void relaunch(ProcessFilter processFilter, JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(null, null, jvmtiFilter, processFilter);
    }

    public static void relaunch(AgentFilter agentFilter, NativeFilter nativeFilter,
                                JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(agentFilter, nativeFilter, jvmtiFilter, null);
    }

    public static void relaunch(AgentFilter agentFilter, ProcessFilter processFilter,
                                JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(agentFilter, null, jvmtiFilter, processFilter);
    }

    public static void relaunch(NativeFilter nativeFilter, ProcessFilter processFilter,
                                JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(null, nativeFilter, jvmtiFilter, processFilter);
    }

    /** Relaunch with all four load-time guards configured explicitly. */
    public static void relaunch(AgentFilter agentFilter, NativeFilter nativeFilter,
                                JvmtiFilter jvmtiFilter, ProcessFilter processFilter) throws RelaunchException {
        relaunchInternal(agentFilter, nativeFilter, jvmtiFilter, processFilter);
    }

    /** Same four-guard relaunch with JVMTI last, matching the pre-existing process-filter position. */
    public static void relaunch(AgentFilter agentFilter, NativeFilter nativeFilter,
                                ProcessFilter processFilter, JvmtiFilter jvmtiFilter) throws RelaunchException {
        relaunchInternal(agentFilter, nativeFilter, jvmtiFilter, processFilter);
    }

    /** Generation of the current JVM in a relaunch chain. Returns 0 for the
     *  original JVM (never relaunched), 1 for the JVM produced by the first
     *  relaunch, 2 for the next, and so on. Read from the property the agent
     *  injects on every relaunched JVM's command line; absent/malformed values
     *  are treated as 0 so a missing property never wedges callers.
     *
     *  ForgeVM does not enforce a relaunch cap of its own — callers express
     *  their stop condition in terms of this value, e.g.
     *  {@code if (ForgeVM.relaunchGeneration() < 3) ForgeVM.relaunch(...);}
     *  for a soft cap, or condition on whatever business state actually
     *  determines whether another relaunch is still useful. */
    public static int relaunchGeneration() {
        String v = System.getProperty(PROP_RELAUNCH_GEN);
        if (v == null) return 0;
        try {
            int n = Integer.parseInt(v.trim());
            return Math.max(n, 0);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    /**
     * Signals the persistent supervisor that the trusted bootstrap policy has
     * been applied in a replacement JVM. Intended for the trusted premain agent
     * named by {@link RelaunchSpec}; ordinary application code has no ready-pipe
     * property in a non-handoff JVM.
     */
    public static boolean signalRelaunchReady() {
        String pipe = System.getProperty("forgevm.relaunch.readyPipe");
        String nonce = System.getProperty("forgevm.relaunch.readyNonce");
        if (pipe == null || pipe.isBlank() || nonce == null || nonce.isBlank()) return false;
        try (RandomAccessFile ready = new RandomAccessFile(pipe, "rw")) {
            ready.write((nonce + "\n").getBytes(StandardCharsets.UTF_8));
            System.clearProperty("forgevm.relaunch.readyNonce");
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    private static void relaunchInternal(AgentFilter agentFilter, NativeFilter nativeFilter,
                                          JvmtiFilter jvmtiFilter, ProcessFilter processFilter) throws RelaunchException {
        AgentSession session = agentSession;
        if (session == null || !session.isAlive()) {
            throw new RelaunchException("agent_not_active");
        }
        try {
            int nextGen = relaunchGeneration() + 1;
            String command = buildRelaunchCommand(agentFilter, nativeFilter, jvmtiFilter, processFilter, nextGen);
            String response = sendCommand(session, command);
            if (!isOkResponse(response)) {
                String reason = "relaunch_rejected";
                if (response != null && !response.isBlank()) {
                    Map<String, String> fields = JsonUtils.parseFlatJsonObject(response);
                    reason = fields.getOrDefault("reason", reason);
                }
                throw new RelaunchException(reason);
            }
            /* Agent acknowledged: JVM termination is imminent. Block here until killed. */
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            throw new RelaunchException("jvm_not_killed");
        } catch (RelaunchException e) {
            throw e;
        } catch (Throwable e) {
            throw new RelaunchException("relaunch_send_failed");
        }
    }

    private static void relaunchV2(RelaunchSpec spec) throws RelaunchException {
        AgentSession session = agentSession;
        if (session == null || !session.isAlive()) {
            throw new RelaunchException("agent_not_active");
        }
        try {
            String response = sendCommand(session, buildRelaunchV2Command(spec));
            if (!isOkResponse(response)) {
                String reason = "relaunch_rejected";
                if (response != null && !response.isBlank()) {
                    Map<String, String> fields = JsonUtils.parseFlatJsonObject(response);
                    reason = fields.getOrDefault("reason", reason);
                }
                throw new RelaunchException(reason);
            }
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            throw new RelaunchException("jvm_not_killed");
        } catch (RelaunchException e) {
            throw e;
        } catch (Throwable e) {
            throw new RelaunchException("relaunch_send_failed");
        }
    }

    private static String buildRelaunchV2Command(RelaunchSpec spec) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"cmd\":\"relaunch_v2\",\"protocol\":2");
        sb.append(",\"pid\":").append(ProcessHandle.current().pid());
        sb.append(",\"existingAgents\":\"")
                .append(spec.existingAgentPolicy().name().toLowerCase())
                .append('"');
        sb.append(",\"sanitizeEnvironment\":").append(spec.sanitizeEnvironment());
        sb.append(",\"rejectArgumentFiles\":").append(spec.rejectArgumentFiles());
        sb.append(",\"handoffPoint\":\"")
                .append(spec.handoffPoint().name().toLowerCase())
                .append('"');
        sb.append(",\"handoffTimeoutMs\":").append(spec.handoffTimeout().toMillis());
        appendTrustedAgent(sb, "trustedNative", spec.trustedNativeAgent());
        appendTrustedAgent(sb, "trustedJava", spec.trustedJavaAgent());
        appendRelaunchFilter(sb, "agent", spec.agentFilter());
        appendRelaunchFilter(sb, "native", spec.nativeFilter());
        appendRelaunchFilter(sb, "jvmti", spec.jvmtiFilter());
        appendRelaunchFilter(sb, "process", spec.processFilter());
        return sb.append('}').toString();
    }

    private static void appendTrustedAgent(StringBuilder sb, String prefix, RelaunchSpec.TrustedAgent agent) {
        sb.append(",\"has").append(Character.toUpperCase(prefix.charAt(0))).append(prefix.substring(1))
                .append("\":").append(agent != null);
        if (agent == null) return;
        sb.append(",\"").append(prefix).append("Path\":\"")
                .append(escapeJson(agent.path().toString())).append('"');
        sb.append(",\"").append(prefix).append("Sha256\":\"")
                .append(agent.sha256()).append('"');
        sb.append(",\"").append(prefix).append("Options\":\"")
                .append(escapeJson(agent.options())).append('"');
    }

    private static void appendRelaunchFilter(StringBuilder sb, String prefix, Object filter) {
        String mode = null;
        List<String> patterns = null;
        if (filter instanceof AgentFilter value) {
            mode = value.mode().name(); patterns = value.patterns();
        } else if (filter instanceof NativeFilter value) {
            mode = value.mode().name(); patterns = value.patterns();
        } else if (filter instanceof JvmtiFilter value) {
            mode = value.mode().name(); patterns = value.patterns();
        } else if (filter instanceof ProcessFilter value) {
            mode = value.mode().name(); patterns = value.patterns();
        }
        String cap = Character.toUpperCase(prefix.charAt(0)) + prefix.substring(1);
        sb.append(",\"has").append(cap).append("Filter\":").append(filter != null);
        if (filter == null) return;
        sb.append(",\"").append(prefix).append("Mode\":\"")
                .append(mode.toLowerCase()).append('"');
        sb.append(",\"").append(prefix).append("Patterns\":[");
        for (int i = 0; i < patterns.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escapeJson(patterns.get(i))).append('"');
        }
        sb.append(']');
    }

    private static String buildRelaunchCommand(AgentFilter agentFilter, NativeFilter nativeFilter,
                                                JvmtiFilter jvmtiFilter, ProcessFilter processFilter, int nextGen) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"cmd\":\"relaunch\"");
        sb.append(",\"pid\":").append(ProcessHandle.current().pid());
        sb.append(",\"nextGen\":").append(nextGen);
        sb.append(",\"hasAgentFilter\":").append(agentFilter != null);
        if (agentFilter != null) {
            sb.append(",\"agentMode\":\"").append(escapeJson(agentFilter.mode().name().toLowerCase())).append("\"");
            sb.append(",\"agentPatterns\":[");
            List<String> ap = agentFilter.patterns();
            for (int i = 0; i < ap.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(ap.get(i))).append('"');
            }
            sb.append(']');
        }
        sb.append(",\"hasNativeFilter\":").append(nativeFilter != null);
        if (nativeFilter != null) {
            sb.append(",\"nativeMode\":\"").append(escapeJson(nativeFilter.mode().name().toLowerCase())).append("\"");
            sb.append(",\"nativePatterns\":[");
            List<String> np = nativeFilter.patterns();
            for (int i = 0; i < np.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(np.get(i))).append('"');
            }
            sb.append(']');
        }
        sb.append(",\"hasJvmtiFilter\":").append(jvmtiFilter != null);
        if (jvmtiFilter != null) {
            sb.append(",\"jvmtiMode\":\"").append(escapeJson(jvmtiFilter.mode().name().toLowerCase())).append("\"");
            sb.append(",\"jvmtiPatterns\":[");
            List<String> jp = jvmtiFilter.patterns();
            for (int i = 0; i < jp.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(jp.get(i))).append('"');
            }
            sb.append(']');
        }
        sb.append(",\"hasProcessFilter\":").append(processFilter != null);
        if (processFilter != null) {
            sb.append(",\"processMode\":\"").append(escapeJson(processFilter.mode().name().toLowerCase())).append("\"");
            sb.append(",\"processPatterns\":[");
            List<String> pp = processFilter.patterns();
            for (int i = 0; i < pp.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(pp.get(i))).append('"');
            }
            sb.append(']');
        }
        sb.append('}');
        return sb.toString();
    }

    private static boolean sendFilterCommand(String cmd, String mode, List<String> patterns) {
        AgentSession session = agentSession;
        if (session == null || !session.isAlive()) {
            return false;
        }
        try {
            String command = buildFilterCommand(cmd, mode, patterns);
            String response = sendCommand(session, command);
            return isOkResponse(response);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String buildFilterCommand(String cmd, String mode, List<String> patterns) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"cmd\":\"").append(escapeJson(cmd)).append("\"");
        if (mode != null) {
            sb.append(",\"mode\":\"").append(escapeJson(mode.toLowerCase())).append("\"");
        }
        if (patterns != null && !patterns.isEmpty()) {
            sb.append(",\"patterns\":[");
            for (int i = 0; i < patterns.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(patterns.get(i))).append('"');
            }
            sb.append(']');
        }
        sb.append('}');
        return sb.toString();
    }

    public static boolean rebindAgentToCurrentJvm() {
        return JvmControl.rebindAgentToCurrentJvm();
    }

    // -- launch internals --

    private static LaunchResult launchInternal() {
        /* Handoff: a persistent agent that survived a relaunch put its PID on
         * our command line. Connect to its named pipe instead of spawning a
         * fresh agent - this is what makes the new JVM's lifecycle fully
         * protected (the same agent that pre-patched ntdll!LdrLoadDll into
         * this JVM while it was still SUSPENDED). */
        String handoffPid = System.getProperty(PROP_AGENT_HANDOFF_PID);
        if (handoffPid != null && !handoffPid.isBlank()) {
            return launchViaHandoff(handoffPid.trim());
        }
        if (relaunchGeneration() > 0) {
            return agentUnavailable("handoff_pid_missing", "");
        }

        Path dllPath = resolveNativeDllPath();
        if (dllPath == null || !Files.exists(dllPath)) {
            clearAgentExitSender();
            clearAgentLockController();
            return agentUnavailable("native_dll_not_found", "");
        }

        Path agentPath = resolveAgentExePath();
        if (agentPath == null || !Files.exists(agentPath)) {
            clearAgentExitSender();
            clearAgentLockController();
            return agentUnavailable("agent_exe_not_found", "");
        }

        try {
            Path logDir = Paths.get("ForgeVM", "logs").toAbsolutePath();
            try { Files.createDirectories(logDir); } catch (Exception ignored) {}

            List<String> agentArgs = new ArrayList<>(List.of(
                    agentPath.toAbsolutePath().toString(),
                    "--serve",
                    option(chars('d', 'l', 'l'), dllPath.toAbsolutePath().toString()),
                    "--logdir=" + logDir
            ));
            /* Optional live status window: requested via launch(options), the
             * -Dforgevm.window property as an external fallback, or forced on
             * when lockJvm is active. Enabled on the persistent (gen0) agent;
             * later JVM generations reach it via handoff, so the flag belongs
             * only on this fresh-spawn path. */
            if (launchOptions.window() || System.getProperty("forgevm.window") != null) {
                agentArgs.add("--window");
            }
            if (launchOptions.lockJvm()) {
                agentArgs.add("--lock-jvm");
            }
            Process process = startProcessReflectively(agentArgs);

            AgentSession session = new AgentSession(
                    process,
                    new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)),
                    new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8))
            );

            String responseLine = sendCommand(session,
                    "{\"cmd\":\"bootstrap\",\"pid\":" + ProcessHandle.current().pid() + "}");
            if (responseLine == null || responseLine.isBlank()) {
                closeAgentSession(session);
                clearAgentExitSender();
                clearAgentLockController();
                return agentUnavailable("agent_empty_response", dllPath.toAbsolutePath().toString());
            }

            LaunchResult result = parseAgentResponse(responseLine, dllPath);
            if (result.agentStatus() != AgentStatus.UNAVAILABLE) {
                agentSession = session;
                registerAgentExitSender(session);
                registerAgentLockController(session);
                return result;
            }

            closeAgentSession(session);
            clearAgentExitSender();
            clearAgentLockController();
            return result;
        } catch (Throwable ex) {
            clearAgentExitSender();
            clearAgentLockController();
            return agentUnavailable("agent_exception:" + ex.getClass().getSimpleName(), "");
        }
    }

    /** Connect to a pre-existing agent via the handoff named pipe.
     *  The pipe is created by the persistent agent at startup with name
     *  {@code \\.\pipe\forgevm_cmd_<agent_pid>}. The short server-publication
     *  race is retried; a relaunched JVM never spawns a second supervisor. */
    private static LaunchResult launchViaHandoff(String agentPid) {
        String pipePath = "\\\\.\\pipe\\forgevm_cmd_" + agentPid;
        Throwable lastFailure = null;
        for (int attempt = 0; attempt < 100; attempt++) {
            try {
                return connectViaHandoff(pipePath);
            } catch (Throwable ex) {
                lastFailure = ex;
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        String detail = lastFailure == null ? "unknown" : lastFailure.getClass().getSimpleName();
        FvmLog.error("persistent-agent handoff failed after retries: " + detail);
        return agentUnavailable("handoff_connect_failed:" + detail, pipePath);
    }

    private static LaunchResult connectViaHandoff(String pipePath) throws Exception {
            /* On Windows, named pipes can be opened with regular file I/O -
             * the kernel handles the pipe protocol transparently. We use
             * RandomAccessFile because it supports full-duplex on a single
             * handle (FileInputStream + FileOutputStream would open two
             * separate handles, exceeding the agent's maxInstances=1). */
            RandomAccessFile raf = new RandomAccessFile(pipePath, "rw");
            FileChannel ch = raf.getChannel();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(Channels.newInputStream(ch), StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(Channels.newOutputStream(ch), StandardCharsets.UTF_8));

            /* process=null marks this as a handoff session - isAlive() returns
             * true until an IPC error, and closeAgentSession skips waitFor. */
            AgentSession session = new AgentSession(null, reader, writer);

            String responseLine = sendCommand(session,
                    "{\"cmd\":\"bootstrap\",\"pid\":" + ProcessHandle.current().pid() + "}");
            if (responseLine == null || responseLine.isBlank()) {
                closeAgentSession(session);
                return agentUnavailable("handoff_empty_response", pipePath);
            }

            /* The agent was already bound to this JVM (the watcher thread
             * re-bootstrapped on jvm.dll load), so the bootstrap reply tells
             * us the current status. */
            Path dllPathPlaceholder = Paths.get(pipePath);
            LaunchResult result = parseAgentResponse(responseLine, dllPathPlaceholder);
            if (result.agentStatus() == AgentStatus.UNAVAILABLE) {
                closeAgentSession(session);
                return result;
            }
            agentSession = session;
            registerAgentExitSender(session);
            registerAgentLockController(session);
            FvmLog.info("ForgeVM connected to persistent agent via " + pipePath);
            return result;
    }

    private static Process startProcessReflectively(List<String> command) throws Exception {
        try {
            Class<?> processBuilderClass = Class.forName(chars(
                    'j', 'a', 'v', 'a', '.', 'l', 'a', 'n', 'g', '.',
                    'P', 'r', 'o', 'c', 'e', 's', 's',
                    'B', 'u', 'i', 'l', 'd', 'e', 'r'));
            Object builder = processBuilderClass
                    .getConstructor(List.class)
                    .newInstance(command);

            processBuilderClass
                    .getMethod(chars('r', 'e', 'd', 'i', 'r', 'e', 'c', 't',
                            'E', 'r', 'r', 'o', 'r', 'S', 't', 'r', 'e', 'a', 'm'), boolean.class)
                    .invoke(builder, true);

            Object process = processBuilderClass
                    .getMethod(chars('s', 't', 'a', 'r', 't'))
                    .invoke(builder);

            return (Process) process;
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof Exception exception) throw exception;
            if (cause instanceof Error error) throw error;
            throw ex;
        }
    }

    private static String chars(char... value) {
        return new String(value);
    }

    private static String option(String name, String value) {
        return "--" + name + "=" + value;
    }

    // -- agent session lifecycle --

    private static void registerAgentExitSender(AgentSession session) {
        clearAgentExitSender();

        JvmControl.ExitCommandSender sender = new JvmControl.ExitCommandSender() {
            @Override
            public boolean isAvailable() {
                return session.isAlive();
            }

            @Override
            public void sendExitCommand(int exitCode) throws Exception {
                long pid = ProcessHandle.current().pid();
                String command = "{\"cmd\":\"exit_jvm\",\"pid\":" + pid + ",\"code\":" + exitCode + "}";
                sendCommand(session, command);
                session.process().waitFor(500, TimeUnit.MILLISECONDS);
            }
        };

        agentExitSender = sender;
        JvmControl.registerExitSender(sender);
    }

    private static void clearAgentExitSender() {
        JvmControl.ExitCommandSender sender = agentExitSender;
        if (sender != null) {
            JvmControl.unregisterExitSender(sender);
            agentExitSender = null;
        }
    }

    private static void registerAgentLockController(AgentSession session) {
        clearAgentLockController();

        JvmControl.AgentLockController controller = new JvmControl.AgentLockController() {
            @Override
            public boolean isAvailable() {
                return session.isAlive();
            }

            @Override
            public boolean lockAgent(int ttlSeconds) throws Exception {
                int safeTtl = Math.max(1, ttlSeconds);
                String response = sendCommand(session, "{\"cmd\":\"lock_agent\",\"ttlSec\":" + safeTtl + "}");
                return isOkResponse(response);
            }

            @Override
            public boolean unlockAgent() throws Exception {
                String response = sendCommand(session, "{\"cmd\":\"unlock_agent\"}");
                return isOkResponse(response);
            }

            @Override
            public boolean rebindAgent(long pid) throws Exception {
                String response = sendCommand(session, "{\"cmd\":\"rebind_jvm\",\"pid\":" + pid + "}");
                return isOkResponse(response);
            }
        };

        agentLockController = controller;
        JvmControl.registerAgentLockController(controller);
    }

    private static void clearAgentLockController() {
        JvmControl.AgentLockController controller = agentLockController;
        if (controller != null) {
            JvmControl.unregisterAgentLockController(controller);
            agentLockController = null;
        }
    }

    // -- agent communication --

    public static String agentSend(String commandJson) {
        AgentSession session = agentSession;
        if (session == null || !session.isAlive()) {
            throw new IllegalStateException("agent_not_active");
        }
        try {
            return sendCommand(session, commandJson);
        } catch (Exception e) {
            throw new IllegalStateException("agent_send_failed:" + e.getMessage(), e);
        }
    }

    static String buildCommand(String cmd, Map<String, String> fields) {
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        joiner.add("\"cmd\":\"" + escapeJson(cmd) + "\"");
        if (fields != null) {
            for (Map.Entry<String, String> entry : fields.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                joiner.add("\"" + escapeJson(key) + "\":\"" + escapeJson(value == null ? "" : value) + "\"");
            }
        }
        return joiner.toString();
    }

    public static String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static boolean isOkResponse(String responseLine) {
        if (responseLine == null || responseLine.isBlank()) {
            return false;
        }
        Map<String, String> fields = JsonUtils.parseFlatJsonObject(responseLine);
        String status = fields.getOrDefault("status", "fallback");
        return "ok".equalsIgnoreCase(status);
    }

    private static String sendCommand(AgentSession session, String commandJson) throws Exception {
        session.ioLock().lock();
        try {
            session.writer().write(commandJson);
            /* Use explicit '\n' rather than BufferedWriter.newLine() (which is
             * \r\n on Windows). After handoff the agent's stdin is in binary
             * mode and an embedded \r would corrupt the trailing JSON field. */
            session.writer().write('\n');
            session.writer().flush();

            CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
                try {
                    return session.reader().readLine();
                } catch (IOException e) {
                    return null;
                }
            });
            return future.get(AGENT_IO_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            session.ioLock().unlock();
        }
    }

    // -- agent response parsing --

    private static LaunchResult parseAgentResponse(String responseLine, Path dllPath) {
        Map<String, String> fields = JsonUtils.parseFlatJsonObject(responseLine);
        String status = fields.getOrDefault("status", "fallback");
        String capability = fields.getOrDefault("capability", "UNAVAILABLE");
        String reason = normalizeReason(fields.getOrDefault("reason", "unknown"));
        String activePath = fields.getOrDefault("dllPath", dllPath.toAbsolutePath().toString());

        AgentStatus level = parseAgentStatus(capability);
        if (!"ok".equalsIgnoreCase(status) || level == AgentStatus.UNAVAILABLE) {
            return agentUnavailable("agent_reported_fallback:" + reason, activePath);
        }

        String structMapReady = fields.getOrDefault("structMapReady", "false");
        if (!"true".equalsIgnoreCase(structMapReady)) {
            return agentUnavailable("agent_structmap_not_ready:" + reason, activePath);
        }

        return new LaunchResult(level, true, activePath, reason);
    }

    // -- path resolution --

    private static Path resolveNativeDllPath() {
        Path fromResource = extractBundledBinary(RESOURCE_DLL_PATH, DLL_FILE);
        if (fromResource != null) return fromResource;

        String fromProperty = System.getProperty(PROP_NATIVE_DLL_PATH);
        if (fromProperty != null && !fromProperty.isBlank()) return Paths.get(fromProperty);

        String fromEnv = System.getenv(ENV_NATIVE_DLL_PATH);
        if (fromEnv != null && !fromEnv.isBlank()) return Paths.get(fromEnv);

        Path fromKnownPaths = lookupKnownLocalDllPaths();
        if (fromKnownPaths != null) return fromKnownPaths;

        return null;
    }

    private static Path resolveAgentExePath() {
        Path fromResource = extractBundledBinary(RESOURCE_AGENT_PATH, AGENT_EXE_FILE);
        if (fromResource != null) return fromResource;

        String fromProperty = System.getProperty(PROP_AGENT_EXE_PATH);
        if (fromProperty != null && !fromProperty.isBlank()) return Paths.get(fromProperty);

        String fromEnv = System.getenv(ENV_AGENT_EXE_PATH);
        if (fromEnv != null && !fromEnv.isBlank()) return Paths.get(fromEnv);

        Path fromKnownPaths = lookupKnownLocalAgentPaths();
        if (fromKnownPaths != null) return fromKnownPaths;

        return null;
    }

    private static Path lookupKnownLocalDllPaths() {
        for (Path candidate : new Path[]{
                Paths.get("native", "win-x64", DLL_FILE),
                Paths.get(DLL_FILE)
        }) {
            Path absolute = candidate.toAbsolutePath();
            if (Files.exists(absolute)) return absolute;
        }
        return null;
    }

    private static Path lookupKnownLocalAgentPaths() {
        for (Path candidate : new Path[]{
                Paths.get("native", "win-x64", AGENT_EXE_FILE),
                Paths.get(AGENT_EXE_FILE)
        }) {
            Path absolute = candidate.toAbsolutePath();
            if (Files.exists(absolute)) return absolute;
        }
        return null;
    }

    private static Path extractBundledBinary(String resourcePath, String targetFileName) {
        try (InputStream input = ForgeVM.class.getResourceAsStream(resourcePath)) {
            if (input == null) return null;
            Path runtimeDir = resolveRuntimeDir();
            Files.createDirectories(runtimeDir);
            Path target = runtimeDir.resolve(targetFileName);
            try {
                Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AccessDeniedException ignored) {
                // File is locked by a running agent process -- reuse it as-is
                if (Files.exists(target)) return target;
                return null;
            }
            return target;
        } catch (IOException ex) {
            FvmLog.warn("extract bundled binary failed: " + targetFileName + ", reason=" + ex.getClass().getSimpleName());
            return null;
        }
    }

    private static Path resolveRuntimeDir() {
        Path projectRuntime = Paths.get(System.getProperty("user.dir"), FORGEVM_RUNTIME_DIR, "runtime", "win-x64");
        if (isWritableDirectory(projectRuntime.getParent())) return projectRuntime;

        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null && !localAppData.isBlank()) {
            return Paths.get(localAppData, "ForgeVM", "runtime", "win-x64");
        }
        return Paths.get(System.getProperty("user.home"), ".forgevm", "runtime", "win-x64");
    }

    private static boolean isWritableDirectory(Path dir) {
        if (dir == null) return false;
        try {
            Files.createDirectories(dir);
            return Files.isDirectory(dir) && Files.isWritable(dir);
        } catch (IOException ignored) {
            return false;
        }
    }

    private static AgentStatus parseAgentStatus(String value) {
        if ("FULL".equalsIgnoreCase(value)) return AgentStatus.FULL;
        if ("RESTRICTED".equalsIgnoreCase(value)) return AgentStatus.RESTRICTED;
        return AgentStatus.UNAVAILABLE;
    }

    private static LaunchResult agentUnavailable(String reason, String dllPath) {
        String normalized = normalizeReason(reason);
        FvmLog.error("launch failed: " + normalized);
        return new LaunchResult(AgentStatus.UNAVAILABLE, false, dllPath, normalized);
    }

    private static String normalizeReason(String reason) {
        if (reason == null || reason.isBlank()) return "unknown";
        return reason
                .replace("assifned", "assigned")
                .replace("assinged", "assigned")
                .replace("CreateProcess error=5", "agent_process_access_denied");
    }

    // -- agent session close --

    private static void closeAgentSession(AgentSession session) {
        try {
            try {
                session.ioLock().lock();
                try {
                    session.writer().write("{\"cmd\":\"shutdown\"}");
                    session.writer().write('\n');
                    session.writer().flush();
                } finally {
                    session.ioLock().unlock();
                }
            } catch (Throwable ignored) {
            }
            if (session.process() != null) {
                try { session.process().waitFor(1500, TimeUnit.MILLISECONDS); } catch (Throwable ignored) {}
            }
            try { session.writer().close(); } catch (Throwable ignored) {}
            try { session.reader().close(); } catch (Throwable ignored) {}
        } catch (Throwable ignored) {
        }
    }

    /** Agent IPC session. {@code process} is non-null when we spawned the agent
     *  ourselves (initial launch) and null when we connected to a pre-existing
     *  agent via the handoff named pipe (post-relaunch). */
    private record AgentSession(
            Process process,
            BufferedReader reader,
            BufferedWriter writer,
            ReentrantLock ioLock
    ) {
        private AgentSession(Process process, BufferedReader reader, BufferedWriter writer) {
            this(process, reader, writer, new ReentrantLock());
        }

        /** Conservative liveness check: when we own the agent process, ask the OS.
         *  In handoff mode we don't own the process, so we trust the IPC until a
         *  read/write fails. */
        boolean isAlive() {
            return process == null || process.isAlive();
        }
    }

    public enum AgentStatus {
        /** Agent is active with full privileges. */
        FULL,
        /** Agent is active with restricted privileges. */
        RESTRICTED,
        /** Agent is unavailable -- all operations will fail. */
        UNAVAILABLE
    }

    public record LaunchResult(
            AgentStatus agentStatus,
            boolean nativeDllActive,
            String nativeDllPath,
            String reason
    ) {}
}
