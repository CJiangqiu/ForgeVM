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
                PrintWriter pw = new PrintWriter(
                        Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.WRITE,
                                StandardOpenOption.APPEND),
                        true /* autoFlush */);
                pw.println();
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
