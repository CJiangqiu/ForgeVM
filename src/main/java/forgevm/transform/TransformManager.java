package forgevm.transform;

import forgevm.core.ForgeVM;
import forgevm.util.FvmLog;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the lifecycle of {@link FvmTransformer} instances.
 * Handles loading, unloading, and dispatching transform requests to the Agent.
 */
public final class TransformManager {

    private final Map<String, LoadedTransformer> loaded = new ConcurrentHashMap<>();

    public TransformManager() {
    }

    /**
     * Load and apply a transformer. The transformer's hook class must already
     * be loaded in the JVM before calling this method.
     *
     * @param transformer the transformer to apply
     * @return true if the transform was successfully applied
     */
    public boolean load(FvmTransformer transformer) {
        if (transformer == null) {
            FvmLog.error("TRANSFORM load: transformer is null");
            return false;
        }

        String desc = transformer.describe();
        String key = transformerKey(transformer);

        if (loaded.containsKey(key)) {
            FvmLog.warn("TRANSFORM load: already loaded — " + desc);
            return true;
        }

        // Resolve user's hook method via reflection
        String hookMethodName = transformer.resolveHookMethodName();
        if (hookMethodName == null) {
            FvmLog.error("TRANSFORM result: FAILED | reason: no public method with FvmCallback parameter found in "
                    + transformer.getClass().getName());
            return false;
        }

        FvmLog.info("TRANSFORM load: " + desc);

        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("TRANSFORM result: FAILED | reason: agent not active");
            return false;
        }

        try {
            String[] candidates = transformer.targetMethodCandidates();
            String lastReason = "no_candidates";

            for (String candidate : candidates) {
                FvmLog.info("TRANSFORM trying method candidate: " + candidate);
                String command = buildLoadCommand(transformer, candidate, hookMethodName);
                String response = ForgeVM.agentSend(command);

                if (response != null && response.contains("\"status\":\"ok\"")) {
                    loaded.put(key, new LoadedTransformer(transformer, key, candidate));
                    FvmLog.info("TRANSFORM result: success | matched: " + candidate + " | " + desc);
                    return true;
                }
                lastReason = extractReason(response);
            }

            FvmLog.error("TRANSFORM result: FAILED | all candidates exhausted | last reason: " + lastReason);
            return false;
        } catch (Exception e) {
            FvmLog.error("TRANSFORM result: FAILED | exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Unload a transformer and restore the original method bytecode.
     *
     * @param transformerClass the class of the transformer to unload
     * @return true if successfully restored
     */
    public boolean unload(Class<? extends FvmTransformer> transformerClass) {
        if (transformerClass == null) {
            FvmLog.error("TRANSFORM unload: transformer class is null");
            return false;
        }

        String key = transformerClass.getName();
        LoadedTransformer entry = loaded.remove(key);
        if (entry == null) {
            FvmLog.warn("TRANSFORM unload: not loaded — " + transformerClass.getName());
            return false;
        }

        FvmLog.info("TRANSFORM unload: " + entry.transformer().describe());

        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("TRANSFORM unload: FAILED | reason: agent not active");
            return false;
        }

        try {
            String command = buildUnloadCommand(entry.transformer(), entry.matchedMethod());
            String response = ForgeVM.agentSend(command);

            if (response == null || !response.contains("\"status\":\"ok\"")) {
                String reason = extractReason(response);
                FvmLog.error("TRANSFORM unload: FAILED | reason: " + reason);
                return false;
            }

            FvmLog.info("TRANSFORM unload: restored original | " + entry.transformer().describe());
            return true;
        } catch (Exception e) {
            FvmLog.error("TRANSFORM unload: FAILED | exception: " + e.getMessage());
            return false;
        }
    }

    public boolean isLoaded(Class<? extends FvmTransformer> transformerClass) {
        return transformerClass != null && loaded.containsKey(transformerClass.getName());
    }

    public int loadedCount() {
        return loaded.size();
    }

    // -- internals --

    private String buildLoadCommand(FvmTransformer transformer, String resolvedMethod,
                                    String hookMethodName) {
        String hookClass = transformer.getClass().getName().replace('.', '/');
        // Hook signature: (Lforgevm/transform/FvmCallback;)V
        String hookDesc = "(Lforgevm/transform/FvmCallback;)V";

        return "{\"cmd\":\"transform_load\""
                + ",\"targetClass\":\"" + esc(transformer.targetClass()) + "\""
                + ",\"targetMethod\":\"" + esc(resolvedMethod) + "\""
                + ",\"targetParamDesc\":\"" + esc(buildParamDescriptor(transformer.targetParams())) + "\""
                + ",\"injectAt\":\"" + transformer.injectAt().name() + "\""
                + ",\"hookClass\":\"" + esc(hookClass) + "\""
                + ",\"hookMethod\":\"" + esc(hookMethodName) + "\""
                + ",\"hookDesc\":\"" + esc(hookDesc) + "\""
                + "}";
    }

    private String buildUnloadCommand(FvmTransformer transformer, String resolvedMethod) {
        return "{\"cmd\":\"transform_unload\""
                + ",\"targetClass\":\"" + esc(transformer.targetClass()) + "\""
                + ",\"targetMethod\":\"" + esc(resolvedMethod) + "\""
                + ",\"targetParamDesc\":\"" + esc(buildParamDescriptor(transformer.targetParams())) + "\""
                + "}";
    }

    private static String buildParamDescriptor(Class<?>[] params) {
        if (params == null || params.length == 0) return "()";
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : params) {
            sb.append(toDescriptor(p));
        }
        sb.append(')');
        return sb.toString();
    }

    private static String toDescriptor(Class<?> type) {
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == float.class) return "F";
        if (type == long.class) return "J";
        if (type == double.class) return "D";
        if (type == void.class) return "V";
        if (type.isArray()) return type.getName().replace('.', '/');
        return "L" + type.getName().replace('.', '/') + ";";
    }

    private static String transformerKey(FvmTransformer transformer) {
        return transformer.getClass().getName();
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

    private record LoadedTransformer(FvmTransformer transformer, String key, String matchedMethod) {}
}
