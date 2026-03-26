package forgevm.forge;

import forgevm.core.ForgeVM;
import forgevm.util.FvmLog;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the lifecycle of {@link FvmIngot} instances.
 * Handles loading, unloading, and dispatching forge requests to the Agent.
 */
public final class ForgeManager {

    private final Map<String, LoadedIngot> loaded = new ConcurrentHashMap<>();

    public ForgeManager() {
    }

    /**
     * Load and apply an ingot. The ingot's hook class must already
     * be loaded in the JVM before calling this method.
     *
     * @param ingot the ingot to apply
     * @return true if the forge was successfully applied
     */
    public boolean load(FvmIngot ingot) {
        if (ingot == null) {
            FvmLog.error("FORGE load: ingot is null");
            return false;
        }

        String desc = ingot.describe();
        String key = ingotKey(ingot);

        if (loaded.containsKey(key)) {
            FvmLog.warn("FORGE load: already loaded — " + desc);
            return true;
        }

        // Resolve user's hook method via reflection
        String hookMethodName = ingot.resolveHookMethodName();
        if (hookMethodName == null) {
            FvmLog.error("FORGE result: FAILED | reason: no public method with FvmCallback parameter found in "
                    + ingot.getClass().getName());
            return false;
        }

        FvmLog.info("FORGE load: " + desc);

        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("FORGE result: FAILED | reason: agent not active");
            return false;
        }

        try {
            String[][] candidates = ingot.candidates();
            String lastReason = "no_candidates";

            for (String[] candidate : candidates) {
                String methodName = candidate[0];
                String paramDesc = candidate[1];
                FvmLog.info("FORGE trying method candidate: " + methodName + paramDesc);
                String command = buildLoadCommand(ingot, methodName, paramDesc, hookMethodName);
                String response = ForgeVM.agentSend(command);

                if (response != null && response.contains("\"status\":\"ok\"")) {
                    loaded.put(key, new LoadedIngot(ingot, key, methodName, paramDesc));
                    FvmLog.info("FORGE result: success | matched: " + methodName + paramDesc + " | " + desc);
                    return true;
                }
                lastReason = extractReason(response);
            }

            FvmLog.error("FORGE result: FAILED | all candidates exhausted | last reason: " + lastReason);
            return false;
        } catch (Exception e) {
            FvmLog.error("FORGE result: FAILED | exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Unload an ingot and restore the original method bytecode.
     *
     * @param ingotClass the class of the ingot to unload
     * @return true if successfully restored
     */
    public boolean unload(Class<? extends FvmIngot> ingotClass) {
        if (ingotClass == null) {
            FvmLog.error("FORGE unload: ingot class is null");
            return false;
        }

        String key = ingotClass.getName();
        LoadedIngot entry = loaded.remove(key);
        if (entry == null) {
            FvmLog.warn("FORGE unload: not loaded — " + ingotClass.getName());
            return false;
        }

        FvmLog.info("FORGE unload: " + entry.ingot().describe());

        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("FORGE unload: FAILED | reason: agent not active");
            return false;
        }

        try {
            String command = buildUnloadCommand(entry.ingot(), entry.matchedMethod(), entry.matchedParamDesc());
            String response = ForgeVM.agentSend(command);

            if (response == null || !response.contains("\"status\":\"ok\"")) {
                String reason = extractReason(response);
                FvmLog.error("FORGE unload: FAILED | reason: " + reason);
                return false;
            }

            FvmLog.info("FORGE unload: restored original | " + entry.ingot().describe());
            return true;
        } catch (Exception e) {
            FvmLog.error("FORGE unload: FAILED | exception: " + e.getMessage());
            return false;
        }
    }

    public boolean isLoaded(Class<? extends FvmIngot> ingotClass) {
        return ingotClass != null && loaded.containsKey(ingotClass.getName());
    }

    public int loadedCount() {
        return loaded.size();
    }

    // -- internals --

    private String buildLoadCommand(FvmIngot ingot, String methodName,
                                    String paramDesc, String hookMethodName) {
        String hookClass = ingot.getClass().getName().replace('.', '/');
        String hookDesc = "(Lforgevm/forge/FvmCallback;)V";

        InjectPoint ip = ingot.injectAt();
        StringBuilder cmd = new StringBuilder();
        cmd.append("{\"cmd\":\"forge_load\"");
        cmd.append(",\"targetClass\":\"").append(esc(ingot.targetClass())).append("\"");
        cmd.append(",\"targetMethod\":\"").append(esc(methodName)).append("\"");
        cmd.append(",\"targetParamDesc\":\"").append(esc(paramDesc)).append("\"");
        cmd.append(",\"injectAt\":\"").append(esc(ip.type())).append("\"");
        if (ip.target() != null) {
            cmd.append(",\"injectTarget\":\"").append(esc(ip.target())).append("\"");
        }
        cmd.append(",\"hookClass\":\"").append(esc(hookClass)).append("\"");
        cmd.append(",\"hookMethod\":\"").append(esc(hookMethodName)).append("\"");
        cmd.append(",\"hookDesc\":\"").append(esc(hookDesc)).append("\"");
        cmd.append(",\"includeSubclasses\":").append(ingot.includeSubclasses());
        cmd.append("}");
        return cmd.toString();
    }

    private String buildUnloadCommand(FvmIngot ingot, String methodName, String paramDesc) {
        return "{\"cmd\":\"forge_unload\""
                + ",\"targetClass\":\"" + esc(ingot.targetClass()) + "\""
                + ",\"targetMethod\":\"" + esc(methodName) + "\""
                + ",\"targetParamDesc\":\"" + esc(paramDesc) + "\""
                + ",\"includeSubclasses\":" + ingot.includeSubclasses()
                + "}";
    }

    private static String ingotKey(FvmIngot ingot) {
        return ingot.getClass().getName();
    }

    private static String extractReason(String response) {
        if (response == null || response.isBlank()) return "empty_response";
        int idx = response.indexOf("\"reason\":\"");
        if (idx >= 0) {
            int start = idx + 10;
            int end = response.indexOf('"', start);
            if (end > start) return response.substring(start, end);
        }
        return response;
    }

    private static String esc(String value) {
        return ForgeVM.escapeJson(value);
    }

    private record LoadedIngot(FvmIngot ingot, String key, String matchedMethod, String matchedParamDesc) {}
}
