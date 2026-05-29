package forgevm.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal ForgeVM logger.
 *
 * Outputs each line to:
 *   1. stderr (for IDE/console visibility)
 *   2. {@code ForgeVM/logs/fvm-java.log} (for post-mortem inspection,
 *      complementing the native-side fvm-agent.log / fvm-transform.log)
 *
 * If the file sink can't be opened (permissions, missing dir, etc.) we
 * silently fall back to stderr-only.
 */
public final class FvmLog {
    private static final String PREFIX = "[FVM] ";
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static volatile PrintWriter fileSink;
    private static volatile boolean fileSinkInitialized;
    private static final Object SINK_LOCK = new Object();

    private FvmLog() {
    }

    public static void error(String message) {
        write("ERROR", message);
    }

    public static void warn(String message) {
        write("WARN ", message);
    }

    public static void info(String message) {
        write("INFO ", message);
    }

    private static void write(String level, String message) {
        String line = FMT.format(LocalDateTime.now()) + " " + level + " " + PREFIX + message;
        System.err.println(line);
        PrintWriter sink = fileSink();
        if (sink != null) {
            synchronized (SINK_LOCK) {
                sink.println(line);
            }
        }
    }

    private static PrintWriter fileSink() {
        if (fileSinkInitialized) return fileSink;
        synchronized (SINK_LOCK) {
            if (fileSinkInitialized) return fileSink;
            try {
                Path logDir = Paths.get("ForgeVM", "logs").toAbsolutePath();
                Files.createDirectories(logDir);
                Path logFile = logDir.resolve("fvm-java.log");
                /* Under dual-loading, ForgeVM (hence FvmLog) is loaded by more
                 * than one classloader, so several FvmLog instances write this
                 * file in the same JVM run. Coordinate via a JVM-global property:
                 * the first instance this run truncates for a clean log; the rest
                 * append, so no classloader clobbers another's session. */
                boolean firstThisRun = System.getProperty("forgevm.javalog.opened") == null;
                if (firstThisRun) System.setProperty("forgevm.javalog.opened", "1");
                StandardOpenOption tail = firstThisRun
                        ? StandardOpenOption.TRUNCATE_EXISTING
                        : StandardOpenOption.APPEND;
                PrintWriter pw = new PrintWriter(
                        Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.WRITE,
                                tail),
                        true /* autoFlush */);
                pw.println("===== ForgeVM Java log session " + FMT.format(LocalDateTime.now()) + " =====");
                fileSink = pw;
            } catch (IOException ignored) {
                // Fall back to stderr-only.
            }
            fileSinkInitialized = true;
        }
        return fileSink;
    }
}
