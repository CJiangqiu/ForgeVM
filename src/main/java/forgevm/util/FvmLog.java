package forgevm.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal ForgeVM logger. Writes to ForgeVM/logs/forgevm.log
 * relative to the working directory, falling back to LOCALAPPDATA or user.home.
 */
public final class FvmLog {
    private static final String PREFIX = "[FVM] ";
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private FvmLog() {
    }

    public static void error(String message) {
        String line = FMT.format(LocalDateTime.now()) + " ERROR " + PREFIX + message;
        System.err.println(line);
        writeToFile(line);
    }

    public static void warn(String message) {
        String line = FMT.format(LocalDateTime.now()) + " WARN  " + PREFIX + message;
        System.err.println(line);
        writeToFile(line);
    }

    public static void info(String message) {
        String line = FMT.format(LocalDateTime.now()) + " INFO  " + PREFIX + message;
        writeToFile(line);
    }

    private static void writeToFile(String line) {
        try {
            Path logFile = resolveLogFile();
            Files.createDirectories(logFile.getParent());
            Files.writeString(logFile, line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // logging must never crash the caller
        }
    }

    private static Path resolveLogFile() {
        Path candidate = Paths.get(System.getProperty("user.dir"), "ForgeVM", "logs", "forgevm.log");
        try {
            Files.createDirectories(candidate.getParent());
            if (Files.isWritable(candidate.getParent())) return candidate;
        } catch (IOException ignored) {
        }

        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null && !localAppData.isBlank()) {
            return Paths.get(localAppData, "ForgeVM", "logs", "forgevm.log");
        }
        return Paths.get(System.getProperty("user.home"), ".forgevm", "logs", "forgevm.log");
    }
}
