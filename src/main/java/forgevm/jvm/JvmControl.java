package forgevm.jvm;

public final class JvmControl {
    private static volatile ExitCommandSender exitSender;
    private static volatile AgentLockController agentLockController;

    private JvmControl() {
    }

    public static boolean exitJvm() {
        return exitJvm(0);
    }

    public static boolean exitJvm(int exitCode) {
        ExitCommandSender sender = exitSender;
        if (sender == null || !sender.isAvailable()) {
            return false;
        }
        try {
            sender.sendExitCommand(exitCode);
            // If Agent succeeded, TerminateProcess kills us — we never reach here.
            // If we're still alive, the kill failed.
            Thread.sleep(1000);
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static void registerExitSender(ExitCommandSender sender) {
        exitSender = sender;
    }

    public static void unregisterExitSender(ExitCommandSender sender) {
        if (exitSender == sender) {
            exitSender = null;
        }
    }

    public static boolean lockAgent(int ttlSeconds) {
        AgentLockController controller = agentLockController;
        if (controller == null || !controller.isAvailable()) {
            return false;
        }
        try {
            return controller.lockAgent(ttlSeconds);
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean lockAgent() {
        AgentLockController controller = agentLockController;
        if (controller == null || !controller.isAvailable()) {
            return false;
        }
        try {
            return controller.lockAgent(0);
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean unlockAgent() {
        AgentLockController controller = agentLockController;
        if (controller == null || !controller.isAvailable()) {
            return false;
        }
        try {
            return controller.unlockAgent();
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean banJavaAgent() {
        return AttachGuard.activate(null);
    }

    public static boolean banJavaAgent(AgentFilter filter) {
        return AttachGuard.activate(filter);
    }

    public static boolean unbanJavaAgent() {
        return AttachGuard.deactivate();
    }

    public static boolean banNativeLoad() {
        return NativeGuard.activate(null);
    }

    public static boolean banNativeLoad(NativeFilter filter) {
        return NativeGuard.activate(filter);
    }

    public static boolean unbanNativeLoad() {
        return NativeGuard.deactivate();
    }

    public static boolean rebindAgentToCurrentJvm() {
        AgentLockController controller = agentLockController;
        if (controller == null || !controller.isAvailable()) {
            return false;
        }
        try {
            return controller.rebindAgent(ProcessHandle.current().pid());
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static void registerAgentLockController(AgentLockController controller) {
        agentLockController = controller;
    }

    public static void unregisterAgentLockController(AgentLockController controller) {
        if (agentLockController == controller) {
            agentLockController = null;
        }
    }

    public interface ExitCommandSender {
        boolean isAvailable();

        void sendExitCommand(int exitCode) throws Exception;
    }

    public interface AgentLockController {
        boolean isAvailable();

        boolean lockAgent(int ttlSeconds) throws Exception;

        boolean unlockAgent() throws Exception;

        boolean rebindAgent(long pid) throws Exception;
    }
}
