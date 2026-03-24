package forgevm.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal ForgeVM logger. Outputs to stderr only.
 * Persistent logs are handled by the native side:
 * fvm-agent.log (Agent lifecycle) and fvm-transform.log (transform details),
 * both written to ForgeVM/logs/.
 */
public final class FvmLog {
    private static final String PREFIX = "[FVM] ";
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private FvmLog() {
    }

    public static void error(String message) {
        System.err.println(FMT.format(LocalDateTime.now()) + " ERROR " + PREFIX + message);
    }

    public static void warn(String message) {
        System.err.println(FMT.format(LocalDateTime.now()) + " WARN  " + PREFIX + message);
    }

    public static void info(String message) {
        System.err.println(FMT.format(LocalDateTime.now()) + " INFO  " + PREFIX + message);
    }
}
