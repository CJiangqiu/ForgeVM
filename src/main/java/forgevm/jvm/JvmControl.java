package forgevm.jvm;

public final class JvmControl {
    private static volatile ExitCommandSender exitSender;
    private static volatile AgentLockController agentLockController;

    private JvmControl() {
    }

    public static void exitJvm() {
        exitJvm(0);
    }

    public static void exitJvm(int exitCode) {
        ExitCommandSender sender = exitSender;
        if (sender != null && sender.isAvailable()) {
            try {
                sender.sendExitCommand(exitCode);
            } catch (Throwable ignored) {
            }
        }

        Runtime.getRuntime().halt(exitCode);
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
