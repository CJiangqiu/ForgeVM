package forgevm.core;

import forgevm.jvm.AgentFilter;
import forgevm.jvm.AttachGuard;
import forgevm.jvm.JvmControl;
import forgevm.jvm.NativeFilter;
import forgevm.jvm.NativeGuard;
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
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public final class ForgeVM {
    private static final String ENV_AGENT_EXE_PATH = "FORGEVM_AGENT_EXE_PATH";
    private static final String PROP_AGENT_EXE_PATH = "forgevm.agent.exe.path";
    private static final String ENV_NATIVE_DLL_PATH = "FORGEVM_NATIVE_DLL_PATH";
    private static final String PROP_NATIVE_DLL_PATH = "forgevm.native.dll.path";

    private static final String AGENT_EXE_FILE = "forgevm_agent.exe";
    private static final String DLL_FILE = "forgevm_native.dll";
    private static final String FORGEVM_RUNTIME_DIR = "ForgeVM";
    private static final String RESOURCE_AGENT_PATH = "/native/win-x64/forgevm_agent.exe";
    private static final String RESOURCE_DLL_PATH = "/native/win-x64/forgevm_native.dll";
    private static final long AGENT_IO_TIMEOUT_SECONDS = 120L;
    private static final String PORT_FILE_PREFIX = "agent_";
    private static final String PORT_FILE_SUFFIX = ".port";

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

    public static final LaunchPermissionPolicy SILENT = LaunchPermissionPolicy.SILENT;
    public static final LaunchPermissionPolicy PROMPT = LaunchPermissionPolicy.PROMPT;

    private ForgeVM() {
    }

    // -- launch --

    public static LaunchResult launch() {
        return launch(LaunchPermissionPolicy.SILENT);
    }

    public static LaunchResult launchPrompt() {
        return launch(LaunchPermissionPolicy.PROMPT);
    }

    public static synchronized LaunchResult launch(LaunchPermissionPolicy policy) {
        LaunchPermissionPolicy effectivePolicy = policy == null ? LaunchPermissionPolicy.SILENT : policy;

        // Check if we already have a working session (same ClassLoader)
        AgentSession currentSession = agentSession;
        if (currentSession != null && !isSessionAlive(currentSession)) {
            clearAgentExitSender();
            clearAgentLockController();
            closeAgentSession(currentSession);
            agentSession = null;
        }

        if (state != null) {
            if (state.nativeDllActive() && agentSession != null && isSessionAlive(agentSession)) {
                return state;
            }
            if (effectivePolicy == LaunchPermissionPolicy.SILENT && agentSession != null) {
                return state;
            }
        }

        // Try to connect to an existing Agent (started by another ClassLoader)
        int existingPort = readPortFile();
        if (existingPort > 0) {
            LaunchResult result = tryConnectExistingAgent(existingPort);
            if (result != null) {
                state = result;
                return result;
            }
        }

        // No existing Agent — start a new one
        LaunchResult result = launchInternal(effectivePolicy);
        state = result;
        return result;
    }

    /**
     * Check if the Agent process is reachable.
     * <p>Does NOT depend on static fields — tries the TCP port file,
     * so it works across ClassLoaders.
     */
    public static boolean isAgentActive() {
        // Fast path: check current session
        AgentSession session = agentSession;
        if (session != null && isSessionAlive(session)) {
            return true;
        }
        // Slow path: check port file for cross-ClassLoader discovery
        int port = readPortFile();
        if (port > 0) {
            try (Socket probe = new Socket("127.0.0.1", port)) {
                return true;
            } catch (IOException ignored) {
            }
        }
        return false;
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

    public static boolean banJavaAgent() {
        return JvmControl.banJavaAgent();
    }

    public static boolean banJavaAgent(AgentFilter filter) {
        return JvmControl.banJavaAgent(filter);
    }

    public static boolean unbanJavaAgent() {
        return JvmControl.unbanJavaAgent();
    }

    public static boolean banNativeLoad() {
        return JvmControl.banNativeLoad();
    }

    public static boolean banNativeLoad(NativeFilter filter) {
        return JvmControl.banNativeLoad(filter);
    }

    public static boolean unbanNativeLoad() {
        return JvmControl.unbanNativeLoad();
    }

    public static boolean purgeAgent(String agentClassName) {
        if (agentClassName == null || agentClassName.isBlank()) {
            return false;
        }
        AgentSession session = agentSession;
        if (session == null || !isSessionAlive(session)) {
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

    /**
     * Try to connect to an already-running Agent via port file.
     * Returns a successful LaunchResult, or null if connection failed.
     */
    private static LaunchResult tryConnectExistingAgent(int port) {
        try {
            Socket socket = new Socket("127.0.0.1", port);
            AgentSession session = new AgentSession(
                    null, // no Process — agent was started by another ClassLoader
                    new BufferedReader(new InputStreamReader(socket.getInputStream())),
                    new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())),
                    new ReentrantLock(),
                    socket
            );

            String responseLine = sendCommand(session,
                    "{\"cmd\":\"bootstrap\",\"pid\":" + ProcessHandle.current().pid() + "}");
            if (responseLine == null || responseLine.isBlank()) {
                closeAgentSession(session);
                return null;
            }

            Map<String, String> fields = JsonUtils.parseFlatJsonObject(responseLine);
            String status = fields.getOrDefault("status", "fallback");
            String capability = fields.getOrDefault("capability", "UNAVAILABLE");
            AgentStatus level = parseAgentStatus(capability);

            if (!"ok".equalsIgnoreCase(status) || level == AgentStatus.UNAVAILABLE) {
                closeAgentSession(session);
                return null;
            }

            agentSession = session;
            registerAgentExitSender(session);
            registerAgentLockController(session);
            AttachGuard.install();
            NativeGuard.install();

            String dllPath = fields.getOrDefault("dllPath", "");
            FvmLog.info("connected to existing Agent on port " + port);
            return new LaunchResult(level, true, dllPath, "connected_existing");
        } catch (Exception e) {
            // Agent not reachable — port file is stale or connection failed
            return null;
        }
    }

    private static LaunchResult launchInternal(LaunchPermissionPolicy policy) {
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

            Process process = new ProcessBuilder(
                    agentPath.toAbsolutePath().toString(),
                    "--serve",
                    "--policy=" + policy.name().toLowerCase(),
                    "--dll=" + dllPath.toAbsolutePath(),
                    "--logdir=" + logDir
            ).redirectErrorStream(false).start();

            // Agent prints {"port":XXXXX} to stdout, then accepts TCP connections
            BufferedReader processReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            String portLine = null;
            try {
                CompletableFuture<String> portFuture = CompletableFuture.supplyAsync(() -> {
                    try { return processReader.readLine(); } catch (IOException e) { return null; }
                });
                portLine = portFuture.get(10, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            if (portLine == null || portLine.isBlank()) {
                process.destroy();
                return agentUnavailable("agent_no_port_response", dllPath.toAbsolutePath().toString());
            }

            Map<String, String> portFields = JsonUtils.parseFlatJsonObject(portLine);
            String portStr = portFields.get("port");
            if (portStr == null || portStr.isBlank()) {
                process.destroy();
                return agentUnavailable("agent_invalid_port_response", dllPath.toAbsolutePath().toString());
            }

            int port = Integer.parseInt(portStr);
            FvmLog.info("Agent listening on port " + port);

            // Write port file for cross-ClassLoader discovery
            writePortFile(port);

            // Connect via TCP
            Socket socket = new Socket("127.0.0.1", port);
            AgentSession session = new AgentSession(
                    process,
                    new BufferedReader(new InputStreamReader(socket.getInputStream())),
                    new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())),
                    new ReentrantLock(),
                    socket
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
                AttachGuard.install();
                NativeGuard.install();
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

    // -- port file --

    private static Path portFilePath() {
        long pid = ProcessHandle.current().pid();
        Path runtimeDir = Paths.get("ForgeVM", "runtime").toAbsolutePath();
        return runtimeDir.resolve(PORT_FILE_PREFIX + pid + PORT_FILE_SUFFIX);
    }

    private static void writePortFile(int port) {
        try {
            Path path = portFilePath();
            Files.createDirectories(path.getParent());
            Files.writeString(path, String.valueOf(port));
            FvmLog.info("port file written: " + path);
        } catch (IOException e) {
            FvmLog.warn("failed to write port file: " + e.getMessage());
        }
    }

    private static int readPortFile() {
        try {
            Path path = portFilePath();
            if (!Files.exists(path)) return -1;
            String content = Files.readString(path).trim();
            if (content.isEmpty()) return -1;
            return Integer.parseInt(content);
        } catch (Exception ignored) {
            return -1;
        }
    }

    // -- agent session lifecycle --

    private static boolean isSessionAlive(AgentSession session) {
        // If we have the process handle, check it
        if (session.process() != null) {
            return session.process().isAlive();
        }
        // No process handle (connected to existing agent) — check socket
        return session.socket() != null && !session.socket().isClosed();
    }

    private static void registerAgentExitSender(AgentSession session) {
        clearAgentExitSender();

        JvmControl.ExitCommandSender sender = new JvmControl.ExitCommandSender() {
            @Override
            public boolean isAvailable() {
                return isSessionAlive(session);
            }

            @Override
            public void sendExitCommand(int exitCode) throws Exception {
                long pid = ProcessHandle.current().pid();
                String command = "{\"cmd\":\"exit_jvm\",\"pid\":" + pid + ",\"code\":" + exitCode + "}";
                sendCommand(session, command);
                if (session.process() != null) {
                    session.process().waitFor(500, TimeUnit.MILLISECONDS);
                }
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
                return isSessionAlive(session);
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
        if (session == null || !isSessionAlive(session)) {
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
                // File is locked by a running agent process — reuse it as-is
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
            try { session.writer().close(); } catch (Throwable ignored) {}
            try { session.reader().close(); } catch (Throwable ignored) {}
            try { if (session.socket() != null) session.socket().close(); } catch (Throwable ignored) {}
            try { if (session.process() != null && session.process().isAlive()) session.process().destroy(); } catch (Throwable ignored) {}
        } catch (Throwable ignored) {
        }
    }

    private record AgentSession(
            Process process,   // null if connected to an existing agent
            BufferedReader reader,
            BufferedWriter writer,
            ReentrantLock ioLock,
            Socket socket
    ) {}

    public enum AgentStatus {
        /** Agent is active with full privileges. */
        FULL,
        /** Agent is active with restricted privileges. */
        RESTRICTED,
        /** Agent is unavailable — all operations will fail. */
        UNAVAILABLE
    }

    public enum LaunchPermissionPolicy {
        /** Silent probe path without proactive elevation prompt. */
        SILENT,
        /** Prompt-capable probe path that may request elevated permission. */
        PROMPT
    }

    public record LaunchResult(
            AgentStatus agentStatus,
            boolean nativeDllActive,
            String nativeDllPath,
            String reason
    ) {}
}
