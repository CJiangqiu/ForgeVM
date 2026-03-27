package forgevm.jvm;

import forgevm.core.ForgeVM;
import forgevm.forge.FvmCallback;
import forgevm.forge.FvmIngot;
import forgevm.util.FvmLog;

/**
 * Guards against unwanted native library loading by hooking
 * {@code Runtime.load0()} and {@code Runtime.loadLibrary0()}.
 *
 * <p>All Java-side native loading flows through these two methods:
 * <ul>
 *   <li>{@code System.load(path)}        → {@code Runtime.load0(callerClass, path)}</li>
 *   <li>{@code System.loadLibrary(name)} → {@code Runtime.loadLibrary0(callerClass, name)}</li>
 *   <li>{@code Runtime.load(path)}       → {@code Runtime.load0(callerClass, path)}</li>
 *   <li>{@code Runtime.loadLibrary(name)}→ {@code Runtime.loadLibrary0(callerClass, name)}</li>
 * </ul>
 *
 * <p>Lifecycle (same pattern as {@link AttachGuard}):
 * <ol>
 *   <li>{@link #install()} — called once during {@code ForgeVM.launch()}.
 *       Installs bytecode hooks. No blocking yet — all calls pass through.</li>
 *   <li>{@link #activate(NativeFilter)} — user calls {@code ForgeVM.banNativeLoad()} /
 *       {@code banNativeLoad(filter)}. Enables blocking with the given filter rules.</li>
 *   <li>{@link #deactivate()} — user calls {@code ForgeVM.unbanNativeLoad()}.
 *       Stops blocking. Hooks remain installed for future re-activation.</li>
 * </ol>
 */
public final class NativeGuard {

    /** Current filter. Only meaningful when {@code active == true}. */
    private static volatile NativeFilter activeFilter;

    /** Whether blocking is currently enabled. */
    private static volatile boolean active;

    /** Whether hooks are installed (regardless of active/inactive). */
    private static volatile boolean installed;

    private NativeGuard() {
    }

    /**
     * Install hooks on {@code Runtime.load0()} and {@code Runtime.loadLibrary0()}.
     * Called once during {@code ForgeVM.launch()}. Hooks are dormant until
     * {@link #activate(NativeFilter)} is called.
     *
     * @return true if at least one hook was successfully installed
     */
    public static boolean install() {
        if (installed) return true;

        boolean loadHooked = ForgeVM.forge().load(new Load0Hook());
        boolean loadLibraryHooked = ForgeVM.forge().load(new LoadLibrary0Hook());

        if (loadHooked || loadLibraryHooked) {
            installed = true;
            FvmLog.info("NATIVE_GUARD: installed (load0=" + loadHooked
                    + ", loadLibrary0=" + loadLibraryHooked + ")");
            return true;
        }

        FvmLog.warn("NATIVE_GUARD: install failed — could not hook Runtime.load0/loadLibrary0");
        return false;
    }

    /**
     * Activate blocking with the given filter.
     *
     * @param filter the filter rules, or {@code null} for BLOCK_ALL
     * @return true if guard is active
     */
    public static boolean activate(NativeFilter filter) {
        if (!installed) {
            install();
        }
        activeFilter = (filter != null) ? filter : NativeFilter.BLOCK_ALL_INSTANCE;
        active = true;
        FvmLog.info("NATIVE_GUARD: activated — " + describeFilter(activeFilter));
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
        FvmLog.info("NATIVE_GUARD: deactivated (hooks remain installed)");
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

    // -- Ingots --

    /**
     * Hooks {@code Runtime.load0(Class, String)}.
     * <p>{@code load0} is the internal entry point for absolute-path native loading.
     * arg0 = caller Class, arg1 = absolute file path.
     */
    public static class Load0Hook extends FvmIngot {
        public Load0Hook() {
            super("java.lang.Runtime", "load0(Ljava/lang/Class;Ljava/lang/String;)");
        }

        public static void onLoad0(FvmCallback callback) {
            if (!active) return; // pass-through when inactive

            String filePath = (String) callback.getArgument(1);
            if (shouldBlock(filePath)) {
                FvmLog.info("NATIVE_GUARD: blocked Runtime.load0(" + filePath + ")");
                callback.cancel();
            }
        }
    }

    /**
     * Hooks {@code Runtime.loadLibrary0(Class, String)}.
     * <p>{@code loadLibrary0} is the internal entry point for library-name native loading.
     * arg0 = caller Class, arg1 = library name (e.g. "awt", "lwjgl").
     */
    public static class LoadLibrary0Hook extends FvmIngot {
        public LoadLibrary0Hook() {
            super("java.lang.Runtime", "loadLibrary0(Ljava/lang/Class;Ljava/lang/String;)");
        }

        public static void onLoadLibrary0(FvmCallback callback) {
            if (!active) return; // pass-through when inactive

            String libName = (String) callback.getArgument(1);
            if (shouldBlock(libName)) {
                FvmLog.info("NATIVE_GUARD: blocked Runtime.loadLibrary0(" + libName + ")");
                callback.cancel();
            }
        }
    }

    // -- Filter logic --

    private static boolean shouldBlock(String nameOrPath) {
        NativeFilter filter = activeFilter;
        if (filter == null) return false;

        if (filter.mode() == NativeFilter.Mode.BLOCK_ALL) {
            return true;
        }

        if (nameOrPath == null) {
            // Unknown path — whitelist blocks, blacklist allows
            return filter.mode() == NativeFilter.Mode.WHITELIST;
        }

        boolean matches = matchesAny(filter.patterns(), nameOrPath);

        if (filter.mode() == NativeFilter.Mode.BLACKLIST) {
            return matches; // block if it matches a blacklisted pattern
        } else {
            // WHITELIST: block if it does NOT match any whitelisted pattern
            return !matches;
        }
    }

    static boolean matchesAny(String[] patterns, String nameOrPath) {
        String normalized = nameOrPath.replace('\\', '/').toLowerCase();
        for (String pattern : patterns) {
            String p = pattern.replace('\\', '/').toLowerCase();
            if (p.startsWith("*") && p.endsWith("*")) {
                if (normalized.contains(p.substring(1, p.length() - 1))) return true;
            } else if (p.startsWith("*")) {
                if (normalized.endsWith(p.substring(1))) return true;
            } else if (p.endsWith("*")) {
                if (normalized.contains(p.substring(0, p.length() - 1))) return true;
            } else {
                if (normalized.contains(p)) return true;
            }
        }
        return false;
    }

    private static String describeFilter(NativeFilter filter) {
        StringBuilder sb = new StringBuilder(filter.mode().name());
        if (filter.mode() != NativeFilter.Mode.BLOCK_ALL) {
            sb.append('(');
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
