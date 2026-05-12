package forgevm.core;

import forgevm.jvm.AgentFilter;
import forgevm.jvm.JvmControl;
import forgevm.jvm.NativeFilter;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public final class ForgeVM {
    private static final String ENV_AGENT_EXE_PATH = "FORGEVM_AGENT_EXE_PATH";
    private static final String PROP_AGENT_EXE_PATH = "forgevm.agent.exe.path";
    private static final String ENV_NATIVE_DLL_PATH = "FORGEVM_NATIVE_DLL_PATH";
    private static final String PROP_NATIVE_DLL_PATH = "forgevm.native." + chars('d', 'l', 'l') + ".path";

    private static final String AGENT_EXE_FILE = "forgevm_agent.exe";
    private static final String DLL_FILE = "forgevm_native" + chars('.', 'd', 'l', 'l');
    private static final String FORGEVM_RUNTIME_DIR = "ForgeVM";
    private static final String RESOURCE_AGENT_PATH = "/native/win-x64/forgevm_agent.exe";
    private static final String RESOURCE_DLL_PATH = "/native/win-x64/" + DLL_FILE;
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

    // -- launch --

    public static synchronized LaunchResult launch() {
        AgentSession currentSession = agentSession;
        if (currentSession != null && !currentSession.process().isAlive()) {
            clearAgentExitSender();
            clearAgentLockController();
            closeAgentSession(currentSession);
            agentSession = null;
        }

        if (state != null && state.nativeDllActive()
                && agentSession != null && agentSession.process().isAlive()) {
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
        return session != null && session.process().isAlive();
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

    public static boolean exit() {
        return JvmControl.exitJvm();
    }

    public static boolean exit(int exitCode) {
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

    /** Block all Java agent attach attempts. */
    public static boolean banJavaAgent() {
        return sendFilterCommand("ban_java_agent", null, null);
    }

    /** Block Java agent attach attempts matching the filter. */
    public static boolean banJavaAgent(AgentFilter filter) {
        return sendFilterCommand("ban_java_agent",
                filter == null ? null : filter.mode().name(),
                filter == null ? null : filter.patterns());
    }

    public static boolean unbanJavaAgent() {
        return sendFilterCommand("unban_java_agent", null, null);
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

    private static boolean sendFilterCommand(String cmd, String mode, List<String> patterns) {
        AgentSession session = agentSession;
        if (session == null || !session.process().isAlive()) {
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

    public static boolean purgeAgent(String agentClassName) {
        if (agentClassName == null || agentClassName.isBlank()) {
            return false;
        }
        AgentSession session = agentSession;
        if (session == null || !session.process().isAlive()) {
            return false;
        }
        try {
            String command = buildCommand("purge_agent", Map.of("agentClass", agentClassName));
            String response = sendCommand(session, command);
            return isOkResponse(response);
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean rebindAgentToCurrentJvm() {
        return JvmControl.rebindAgentToCurrentJvm();
    }

    // -- launch internals --

    private static LaunchResult launchInternal() {
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

            Process process = startProcessReflectively(List.of(
                    agentPath.toAbsolutePath().toString(),
                    "--serve",
                    option(chars('d', 'l', 'l'), dllPath.toAbsolutePath().toString()),
                    "--logdir=" + logDir
            ));

            AgentSession session = new AgentSession(
                    process,
                    new BufferedReader(new InputStreamReader(process.getInputStream())),
                    new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))
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
                return session.process().isAlive();
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
                return session.process().isAlive();
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
        if (session == null || !session.process().isAlive()) {
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
            session.writer().newLine();
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
                    session.writer().newLine();
                    session.writer().flush();
                } finally {
                    session.ioLock().unlock();
                }
            } catch (Throwable ignored) {
            }
            try { session.process().waitFor(1500, TimeUnit.MILLISECONDS); } catch (Throwable ignored) {}
            try { session.writer().close(); } catch (Throwable ignored) {}
            try { session.reader().close(); } catch (Throwable ignored) {}
        } catch (Throwable ignored) {
        }
    }

    private record AgentSession(
            Process process,
            BufferedReader reader,
            BufferedWriter writer,
            ReentrantLock ioLock
    ) {
        private AgentSession(Process process, BufferedReader reader, BufferedWriter writer) {
            this(process, reader, writer, new ReentrantLock());
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
