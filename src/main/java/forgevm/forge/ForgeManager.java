package forgevm.forge;

import forgevm.core.ForgeVM;
import forgevm.util.FvmLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the lifecycle of {@link FvmIngot} instances.
 * Handles loading, unloading, and dispatching forge requests to the Agent.
 *
 * <p>All entry points funnel into a single batch IPC command
 * ({@code forge_batch_plan}). The Agent groups by target class and commits
 * each class plan atomically (one Suspend / one swap / one optional deopt
 * sweep). On unknown_command response (Native side not yet updated to support
 * the new protocol), this class transparently falls back to the legacy
 * per-ingot {@code forge_load} loop.
 */
public final class ForgeManager {

    private final Map<String, LoadedIngot> loaded = new ConcurrentHashMap<>();

    public ForgeManager() {
    }

    public boolean load(FvmIngot ingot) {
        if (ingot == null) {
            FvmLog.error("FORGE load: ingot is null");
            return false;
        }
        return loadBatch(List.of(ingot)) > 0;
    }

    /**
     * Load and apply multiple ingots as a single batch. The Agent processes the
     * whole batch as one or more class plans (one plan per target class),
     * committing each plan atomically and running a single deopt sweep at the
     * end of the batch.
     *
     * <p>Per-ingot success/failure is reported via {@link FvmLog} as usual.
     * Returns the number of ingots successfully applied.
     */
    public int load(FvmIngot... ingots) {
        if (ingots == null || ingots.length == 0) return 0;
        return loadBatch(Arrays.asList(ingots));
    }

    public int load(Iterable<? extends FvmIngot> ingots) {
        if (ingots == null) return 0;
        ArrayList<FvmIngot> list = new ArrayList<>();
        for (FvmIngot ig : ingots) {
            if (ig != null) list.add(ig);
        }
        if (list.isEmpty()) return 0;
        return loadBatch(list);
    }

    private int loadBatch(List<? extends FvmIngot> ingots) {
        // Pre-pass: filter null / already-loaded, resolve hook method
        List<PreparedIngot> prepared = new ArrayList<>();
        for (FvmIngot ingot : ingots) {
            if (ingot == null) continue;
            String key = ingotKey(ingot);
            if (loaded.containsKey(key)) {
                FvmLog.warn("FORGE load: already loaded -- " + ingot.describe());
                continue;
            }
            String hookMethodName = ingot.resolveHookMethodName();
            if (hookMethodName == null) {
                FvmLog.error("FORGE result: FAILED | reason: no public method with FvmCallback parameter found in "
                        + ingot.getClass().getName());
                continue;
            }
            prepared.add(new PreparedIngot(ingot, key, hookMethodName));
        }
        if (prepared.isEmpty()) return 0;

        /* The agent connection is per-classloader state. Under dual-loading, the
         * classloader that registers ingots (late, when target classes are
         * linked) is often not the one that first launched. Since the agent is a
         * single shared process reachable via the JVM-global handoff pipe, just
         * launch() here too: in a relaunched JVM that connects to the existing
         * agent (no new process), giving this classloader its own command
         * channel. */
        if (!ForgeVM.isAgentActive()) {
            ForgeVM.launch();
        }
        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("FORGE result: FAILED | reason: agent not active");
            return 0;
        }

        FvmLog.info("FORGE batch load: " + prepared.size() + " ingot(s)");
        long startMs = System.currentTimeMillis();

        String response = ForgeVM.agentSend(buildBatchPlanCommand(prepared));
        String reason = extractReason(response);

        if (isUnknownCommand(reason)) {
            FvmLog.warn("FORGE batch load: agent does not support forge_batch_plan, falling back to legacy path");
            return legacyLoadLoop(prepared);
        }

        int succeeded = parseAndRecord(prepared, response);
        long elapsedMs = System.currentTimeMillis() - startMs;
        FvmLog.info("FORGE batch load: " + succeeded + "/" + prepared.size() + " ingot(s) in " + elapsedMs + "ms");
        return succeeded;
    }

    /**
     * Trigger a single global deoptimization sweep on the target JVM.
     */
    public boolean forceDeoptNow() {
        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("FORGE force_deopt: FAILED | reason: agent not active");
            return false;
        }
        String response = ForgeVM.agentSend("{\"cmd\":\"force_deopt\"}");
        if (response != null && response.contains("\"status\":\"ok\"")) {
            return true;
        }
        FvmLog.error("FORGE force_deopt: FAILED | reason: " + extractReason(response));
        return false;
    }

    /**
     * Unload an ingot and restore the original method bytecode.
     *
     * <p>Because the native Agent restores bytecode at the <em>class</em> level (one atomic
     * rollback per InstanceKlass), any other ingots loaded on the same target class are also
     * reverted by the underlying call. This method handles that transparently: sibling
     * ingots sharing the same {@code targetClass} are removed from the active set and then
     * re-applied automatically after the class restore completes.
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
        LoadedIngot entry = loaded.get(key);
        if (entry == null) {
            FvmLog.warn("FORGE unload: not loaded -- " + ingotClass.getName());
            return false;
        }

        String targetClass = entry.ingot().targetClass();
        boolean includeSubclasses = entry.ingot().includeSubclasses();

        /* Native restoreClassPlan reverts the entire InstanceKlass plan (all hooks on the class).
         * With includeSubclasses=true, the Native side also reverts plans for every loaded subclass.
         * Collect survivors -- ingots whose patches were erased and must be re-applied. */
        List<LoadedIngot> survivors = new ArrayList<>();
        for (LoadedIngot li : loaded.values()) {
            if (li.key().equals(key)) continue;
            String liTarget = li.ingot().targetClass();
            if (targetClass.equals(liTarget)
                    || (includeSubclasses && isSubclassOf(liTarget, targetClass))) {
                survivors.add(li);
            }
        }

        // Remove from map first so map state stays consistent with Native state during the call.
        loaded.remove(key);
        for (LoadedIngot s : survivors) loaded.remove(s.key());

        FvmLog.info("FORGE unload: " + entry.ingot().describe()
                + (survivors.isEmpty() ? "" : " [" + survivors.size() + " sibling(s) will be re-applied]"));

        if (!ForgeVM.isAgentActive()) {
            FvmLog.error("FORGE unload: FAILED | reason: agent not active");
            return false;
        }

        // Try new class-level unload first; fall back to legacy per-ingot unload.
        boolean unloadOk = sendClassUnload(targetClass, includeSubclasses);
        if (!unloadOk) {
            FvmLog.warn("FORGE unload: class-level unload failed, falling back to legacy path");
            unloadOk = legacyUnloadOne(entry);
        }

        if (!unloadOk) {
            // Reverse the map removals so state matches reality.
            loaded.put(key, entry);
            for (LoadedIngot s : survivors) loaded.put(s.key(), s);
            return false;
        }

        FvmLog.info("FORGE unload: restored original | " + entry.ingot().describe());

        if (!survivors.isEmpty()) {
            FvmLog.info("FORGE unload: re-applying " + survivors.size() + " sibling(s)");
            List<FvmIngot> reapply = new ArrayList<>();
            for (LoadedIngot s : survivors) reapply.add(s.ingot());
            loadBatch(reapply);
        }
        return true;
    }

    public boolean isLoaded(Class<? extends FvmIngot> ingotClass) {
        return ingotClass != null && loaded.containsKey(ingotClass.getName());
    }

    public int loadedCount() {
        return loaded.size();
    }

    /* ============================================================
     * Legacy fallback path (per-ingot forge_load / forge_unload).
     * Active only when Native side has not yet been updated to support
     * forge_batch_plan / forge_class_unload (returns "unknown_command").
     * ============================================================ */

    private int legacyLoadLoop(List<PreparedIngot> prepared) {
        int succeeded = 0;
        long startMs = System.currentTimeMillis();
        boolean deferDeopt = prepared.size() > 1;
        for (PreparedIngot p : prepared) {
            if (legacyLoadOne(p, deferDeopt)) succeeded++;
        }
        long applyMs = System.currentTimeMillis() - startMs;
        if (deferDeopt) {
            forceDeoptNow();
        }
        long totalMs = System.currentTimeMillis() - startMs;
        FvmLog.info("FORGE legacy load: " + succeeded + "/" + prepared.size()
                + " ingot(s) in " + totalMs + "ms (apply " + applyMs + "ms)");
        return succeeded;
    }

    private boolean legacyLoadOne(PreparedIngot p, boolean deferDeopt) {
        FvmIngot ingot = p.ingot;
        FvmLog.info("FORGE load: " + ingot.describe());
        try {
            String[][] candidates = ingot.candidates();
            String lastReason = "no_candidates";
            for (String[] candidate : candidates) {
                String methodName = candidate[0];
                String paramDesc = candidate[1];
                FvmLog.info("FORGE trying method candidate: " + methodName + paramDesc);
                String command = buildLegacyLoadCommand(ingot, methodName, paramDesc, p.hookMethodName, deferDeopt);
                String response = ForgeVM.agentSend(command);
                if (response != null && response.contains("\"status\":\"ok\"")) {
                    loaded.put(p.key, new LoadedIngot(ingot, p.key, methodName, paramDesc));
                    FvmLog.info("FORGE result: success | matched: " + methodName + paramDesc + " | " + ingot.describe());
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

    private boolean legacyUnloadOne(LoadedIngot entry) {
        try {
            String command = buildLegacyUnloadCommand(entry.ingot(), entry.matchedMethod(), entry.matchedParamDesc());
            String response = ForgeVM.agentSend(command);
            if (response == null || !response.contains("\"status\":\"ok\"")) {
                FvmLog.error("FORGE unload: FAILED | reason: " + extractReason(response));
                return false;
            }
            return true;
        } catch (Exception e) {
            FvmLog.error("FORGE unload: FAILED | exception: " + e.getMessage());
            return false;
        }
    }

    /* ============================================================
     * IPC builders
     * ============================================================ */

    private String buildBatchPlanCommand(List<PreparedIngot> prepared) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"cmd\":\"forge_batch_plan\",\"ingots\":[");
        for (int i = 0; i < prepared.size(); i++) {
            if (i > 0) sb.append(',');
            appendIngotJson(sb, prepared.get(i));
        }
        sb.append("]}");
        return sb.toString();
    }

    private void appendIngotJson(StringBuilder sb, PreparedIngot p) {
        FvmIngot ingot = p.ingot;
        InjectPoint ip = ingot.injectAt();
        String hookClass = ingot.getClass().getName().replace('.', '/');
        String hookDesc = "(Lforgevm/forge/FvmCallback;)V";

        sb.append('{');
        sb.append("\"targetClass\":\"").append(esc(ingot.targetClass())).append('"');
        sb.append(",\"includeSubclasses\":").append(ingot.includeSubclasses());
        sb.append(",\"injectAt\":\"").append(esc(ip.type())).append('"');
        if (ip.target() != null) {
            sb.append(",\"injectTarget\":\"").append(esc(ip.target())).append('"');
        }
        sb.append(",\"hookClass\":\"").append(esc(hookClass)).append('"');
        sb.append(",\"hookMethod\":\"").append(esc(p.hookMethodName)).append('"');
        sb.append(",\"hookDesc\":\"").append(esc(hookDesc)).append('"');
        sb.append(",\"candidates\":[");
        String[][] cands = ingot.candidates();
        for (int j = 0; j < cands.length; j++) {
            if (j > 0) sb.append(',');
            sb.append("{\"methodName\":\"").append(esc(cands[j][0])).append('"');
            sb.append(",\"paramDesc\":\"").append(esc(cands[j][1])).append("\"}");
        }
        sb.append("]}");
    }

    private String buildLegacyLoadCommand(FvmIngot ingot, String methodName,
                                          String paramDesc, String hookMethodName,
                                          boolean deferDeopt) {
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
        if (deferDeopt) {
            cmd.append(",\"deferDeopt\":true");
        }
        cmd.append("}");
        return cmd.toString();
    }

    private String buildLegacyUnloadCommand(FvmIngot ingot, String methodName, String paramDesc) {
        return "{\"cmd\":\"forge_unload\""
                + ",\"targetClass\":\"" + esc(ingot.targetClass()) + "\""
                + ",\"targetMethod\":\"" + esc(methodName) + "\""
                + ",\"targetParamDesc\":\"" + esc(paramDesc) + "\""
                + ",\"includeSubclasses\":" + ingot.includeSubclasses()
                + "}";
    }

    private boolean sendClassUnload(String targetClass, boolean includeSubclasses) {
        String cmd = "{\"cmd\":\"forge_class_unload\""
                + ",\"targetClass\":\"" + esc(targetClass) + "\""
                + ",\"includeSubclasses\":" + includeSubclasses
                + "}";
        String response = ForgeVM.agentSend(cmd);
        if (response != null && response.contains("\"status\":\"ok\"")) {
            return true;
        }
        String reason = extractReason(response);
        if (isUnknownCommand(reason)) {
            return false;
        }
        FvmLog.error("FORGE class_unload: FAILED | reason: " + reason);
        return false;
    }

    /* ============================================================
     * Response parsing
     * ============================================================ */

    /**
     * Parse the per-ingot results array out of a batch_plan response and
     * record successful entries into the loaded map. Returns the count of
     * successful entries.
     *
     * <p>Expected response format:
     * {@code {"status":"ok","results":[{"matched":true,"methodName":"...","paramDesc":"..."},
     *                                   {"matched":false,"reason":"..."}, ...]}}
     */
    private int parseAndRecord(List<PreparedIngot> prepared, String response) {
        if (response == null || response.isBlank()) {
            FvmLog.error("FORGE batch load: empty response");
            return 0;
        }
        if (!response.contains("\"status\":\"ok\"") && !response.contains("\"results\":")) {
            FvmLog.error("FORGE batch load: FAILED | reason: " + extractReason(response));
            return 0;
        }

        List<ResultEntry> results = parseResultsArray(response);
        if (results.size() != prepared.size()) {
            FvmLog.error("FORGE batch load: result count mismatch (" + results.size()
                    + " vs " + prepared.size() + " expected)");
            return 0;
        }

        int succeeded = 0;
        for (int i = 0; i < prepared.size(); i++) {
            PreparedIngot p = prepared.get(i);
            ResultEntry r = results.get(i);
            if (r.matched) {
                loaded.put(p.key, new LoadedIngot(p.ingot, p.key, r.methodName, r.paramDesc));
                FvmLog.info("FORGE result: success | matched: " + r.methodName + r.paramDesc
                        + " | " + p.ingot.describe());
                succeeded++;
            } else {
                FvmLog.error("FORGE result: FAILED | reason: " + r.reason
                        + " | " + p.ingot.describe());
            }
        }
        return succeeded;
    }

    /**
     * Lightweight scan-based parser for the {@code "results":[...]} array.
     * Extracts {@code matched/methodName/paramDesc/reason} fields per entry,
     * relying on the well-formed JSON emitted by the Native side. Not a
     * general-purpose JSON parser.
     */
    private static List<ResultEntry> parseResultsArray(String response) {
        List<ResultEntry> out = new ArrayList<>();
        int idx = response.indexOf("\"results\":");
        if (idx < 0) return out;
        int arrStart = response.indexOf('[', idx);
        if (arrStart < 0) return out;
        int depth = 0;
        int objStart = -1;
        for (int i = arrStart; i < response.length(); i++) {
            char c = response.charAt(i);
            if (c == '{') {
                if (depth == 0) objStart = i;
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && objStart >= 0) {
                    out.add(parseSingleResult(response.substring(objStart, i + 1)));
                    objStart = -1;
                }
            } else if (c == ']' && depth == 0) {
                break;
            }
        }
        return out;
    }

    private static ResultEntry parseSingleResult(String obj) {
        ResultEntry r = new ResultEntry();
        r.matched = obj.contains("\"matched\":true");
        r.methodName = extractStringField(obj, "methodName");
        r.paramDesc  = extractStringField(obj, "paramDesc");
        r.reason     = extractStringField(obj, "reason");
        return r;
    }

    private static String extractStringField(String obj, String key) {
        String needle = "\"" + key + "\":\"";
        int i = obj.indexOf(needle);
        if (i < 0) return "";
        int start = i + needle.length();
        int end = obj.indexOf('"', start);
        if (end < 0) return "";
        return obj.substring(start, end);
    }

    private static String extractReason(String response) {
        if (response == null || response.isBlank()) return "empty_response";
        return extractStringField(response, "reason");
    }

    private static boolean isUnknownCommand(String reason) {
        if (reason == null) return false;
        return reason.equals("unknown_command")
                || reason.contains("not_implemented")
                || reason.contains("not_exported");
    }

    /* ============================================================
     * Helpers
     * ============================================================ */

    private static String ingotKey(FvmIngot ingot) {
        return ingot.getClass().getName();
    }

    private static boolean isSubclassOf(String candidateClass, String parentClass) {
        try {
            Class<?> candidate = Class.forName(candidateClass);
            Class<?> parent    = Class.forName(parentClass);
            return parent.isAssignableFrom(candidate) && !candidate.equals(parent);
        } catch (ClassNotFoundException | LinkageError ignored) {
            return false;
        }
    }

    private static String esc(String value) {
        return ForgeVM.escapeJson(value);
    }

    private static final class PreparedIngot {
        final FvmIngot ingot;
        final String key;
        final String hookMethodName;

        PreparedIngot(FvmIngot ingot, String key, String hookMethodName) {
            this.ingot = ingot;
            this.key = key;
            this.hookMethodName = hookMethodName;
        }
    }

    private static final class ResultEntry {
        boolean matched;
        String methodName = "";
        String paramDesc  = "";
        String reason     = "";
    }

    private record LoadedIngot(FvmIngot ingot, String key, String matchedMethod, String matchedParamDesc) {}
}
