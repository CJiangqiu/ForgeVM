package forgevm.core;

/**
 * Thrown when a ForgeVM operation cannot be executed,
 * typically because the native agent is unavailable.
 * All messages are prefixed with [FGM] for easy identification in logs.
 */
public final class ForgeVMException extends RuntimeException {
    public ForgeVMException(String reason) {
        super("[FVM] " + reason);
    }
}
