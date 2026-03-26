package forgevm.jvm;

import forgevm.core.ForgeVM;
import forgevm.transform.FvmCallback;
import forgevm.transform.FvmTransformer;
import forgevm.util.FvmLog;

import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Guards against unwanted Java agent attachment by hooking
 * {@code VirtualMachine.attach()} and {@code HotSpotVirtualMachine.loadAgent()}.
 *
 * <p>Lifecycle:
 * <ol>
 *   <li>{@link #install()} — called once during {@code ForgeVM.launch()}.
 *       Installs bytecode hooks. No blocking yet — all calls pass through.</li>
 *   <li>{@link #activate(AgentFilter)} — user calls {@code ForgeVM.banJavaAgent()} / {@code banJavaAgent(filter)}.
 *       Enables blocking with the given filter rules.</li>
 *   <li>{@link #deactivate()} — user calls {@code ForgeVM.unbanJavaAgent()}.
 *       Stops blocking. Hooks remain installed for future re-activation.</li>
 * </ol>
 */
public final class AttachGuard {

    /** Current filter. Only meaningful when {@code active == true}. */
    private static volatile AgentFilter activeFilter;

    /** Whether blocking is currently enabled. */
    private static volatile boolean active;

    /** Whether hooks are installed (regardless of active/inactive). */
    private static volatile boolean installed;

    private AttachGuard() {
    }

    /**
     * Install hooks on {@code VirtualMachine.attach()} and {@code loadAgent()}.
     * Called once during {@code ForgeVM.launch()}. Hooks are dormant until
     * {@link #activate(AgentFilter)} is called.
     *
     * @return true if at least one hook was successfully installed
     */
    public static boolean install() {
        if (installed) return true;

        preloadTargetClasses();

        boolean attachHooked = ForgeVM.transformer().load(new AttachHook());
        boolean loadAgentHooked = ForgeVM.transformer().load(new LoadAgentHook());

        if (attachHooked || loadAgentHooked) {
            installed = true;
            FvmLog.info("ATTACH_GUARD: installed (attach=" + attachHooked
                    + ", loadAgent=" + loadAgentHooked + ")");
            return true;
        }

        FvmLog.warn("ATTACH_GUARD: install failed — target classes may not be loaded yet");
        return false;
    }

    /**
     * Activate blocking with the given filter.
     *
     * @param filter the filter rules, or {@code null} for BLOCK_ALL
     * @return true if guard is active
     */
    public static boolean activate(AgentFilter filter) {
        if (!installed) {
            install();
        }
        activeFilter = (filter != null) ? filter : AgentFilter.BLOCK_ALL_INSTANCE;
        active = true;
        FvmLog.info("ATTACH_GUARD: activated — " + describeFilter(activeFilter));
        return installed;
    }

    /**
     * Deactivate blocking. Hooks remain installed for future re-activation.
     */
    public static boolean deactivate() {
        if (!active) {
            return true; // already inactive
        }
        active = false;
        activeFilter = null;
        FvmLog.info("ATTACH_GUARD: deactivated (hooks remain installed)");
        return true;
    }

    /** Whether hooks are installed. */
    public static boolean isInstalled() {
        return installed;
    }

    /** Whether blocking is currently active. */
    public static boolean isActive() {
        return installed && active;
    }

    // -- Transformers --

    /**
     * Hooks {@code VirtualMachine.attach(String)}.
     * When filter is BLOCK_ALL: blocks the attach entirely.
     * When filter is BLACKLIST/WHITELIST: allows attach (filtering at loadAgent level).
     * When no filter: pass-through.
     */
    public static class AttachHook extends FvmTransformer {
        public AttachHook() {
            super("com.sun.tools.attach.VirtualMachine", "attach(Ljava/lang/String;)");
        }

        public static void onAttach(FvmCallback callback) {
            if (!active) return; // pass-through when inactive

            AgentFilter filter = activeFilter;
            if (filter.mode() == AgentFilter.Mode.BLOCK_ALL) {
                FvmLog.info("ATTACH_GUARD: blocked VirtualMachine.attach() [BLOCK_ALL]");
                callback.setReturnValue(null);
            }
            // BLACKLIST / WHITELIST: allow attach, filter at loadAgent level
        }
    }

    /**
     * Hooks {@code HotSpotVirtualMachine.loadAgent(String, String)}.
     * Checks the JAR path (first parameter) against filter rules.
     */
    public static class LoadAgentHook extends FvmTransformer {
        public LoadAgentHook() {
            super("sun.tools.attach.HotSpotVirtualMachine",
                    "loadAgent(Ljava/lang/String;Ljava/lang/String;)");
        }

        public static void onLoadAgent(FvmCallback callback) {
            if (!active) return; // pass-through when inactive

            AgentFilter filter = activeFilter;
            if (filter.mode() == AgentFilter.Mode.BLOCK_ALL) {
                FvmLog.info("ATTACH_GUARD: blocked loadAgent() [BLOCK_ALL]");
                callback.cancel();
                return;
            }

            // loadAgent(String jarPath, String options) → arg0 = jarPath
            String jarPath = (String) callback.getArgument(0);
            if (jarPath == null) {
                // Cannot determine jar path — safe default
                if (filter.mode() == AgentFilter.Mode.WHITELIST) {
                    FvmLog.info("ATTACH_GUARD: blocked loadAgent() [WHITELIST, unknown jar]");
                    callback.cancel();
                }
                return;
            }

            boolean matches = matchesFilter(filter, jarPath);

            if (filter.mode() == AgentFilter.Mode.BLACKLIST && matches) {
                FvmLog.info("ATTACH_GUARD: blocked loadAgent(" + jarPath + ") [BLACKLIST match]");
                callback.cancel();
            } else if (filter.mode() == AgentFilter.Mode.WHITELIST && !matches) {
                FvmLog.info("ATTACH_GUARD: blocked loadAgent(" + jarPath + ") [WHITELIST no match]");
                callback.cancel();
            } else {
                FvmLog.info("ATTACH_GUARD: allowed loadAgent(" + jarPath + ") [" + filter.mode() + "]");
            }
        }
    }

    // -- Filter matching (ready for when argument access is available) --

    static boolean matchesFilter(AgentFilter filter, String jarPath) {
        if (filter.target() == AgentFilter.Target.JAR) {
            return matchesJarPath(filter.patterns(), jarPath);
        } else {
            String agentClass = readAgentClassFromJar(jarPath);
            if (agentClass == null) return false;
            return matchesPackagePrefix(filter.patterns(), agentClass);
        }
    }

    static boolean matchesPackagePrefix(String[] prefixes, String className) {
        for (String prefix : prefixes) {
            if (className.startsWith(prefix)) return true;
        }
        return false;
    }

    static boolean matchesJarPath(String[] globs, String jarPath) {
        String normalized = jarPath.replace('\\', '/').toLowerCase();
        for (String glob : globs) {
            String pattern = glob.replace('\\', '/').toLowerCase();
            if (pattern.startsWith("*") && pattern.endsWith("*")) {
                if (normalized.contains(pattern.substring(1, pattern.length() - 1))) return true;
            } else if (pattern.startsWith("*")) {
                if (normalized.endsWith(pattern.substring(1))) return true;
            } else if (pattern.endsWith("*")) {
                if (normalized.contains(pattern.substring(0, pattern.length() - 1))) return true;
            } else {
                if (normalized.contains(pattern)) return true;
            }
        }
        return false;
    }

    static String readAgentClassFromJar(String jarPath) {
        try (JarFile jar = new JarFile(jarPath)) {
            Manifest manifest = jar.getManifest();
            if (manifest == null) return null;
            String agentClass = manifest.getMainAttributes().getValue("Agent-Class");
            if (agentClass == null) {
                agentClass = manifest.getMainAttributes().getValue("Premain-Class");
            }
            return agentClass;
        } catch (Exception e) {
            FvmLog.warn("ATTACH_GUARD: failed to read manifest from " + jarPath
                    + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Force-load Attach API classes so the Agent can find them in the class dictionary.
     * These classes live in jdk.attach and are lazily loaded — they won't exist
     * until someone references them.
     */
    private static void preloadTargetClasses() {
        try { Class.forName("com.sun.tools.attach.VirtualMachine"); } catch (Throwable ignored) {}
        try { Class.forName("sun.tools.attach.HotSpotVirtualMachine"); } catch (Throwable ignored) {}
    }

    private static String describeFilter(AgentFilter filter) {
        StringBuilder sb = new StringBuilder(filter.mode().name());
        if (filter.mode() != AgentFilter.Mode.BLOCK_ALL) {
            sb.append('(').append(filter.target().name()).append(": ");
            String[] p = filter.patterns();
            for (int i = 0; i < p.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(p[i]);
            }
            sb.append(')');
        }
        return sb.toString();
    }
}
