package forgevm.core;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/** One client's channel, not ownership of the shared agent's lifetime. */
final class AgentSession {
    private final Process process;
    private final BufferedReader reader;
    private final BufferedWriter writer;
    private final AutoCloseable transport;
    private final ReentrantLock ioLock = new ReentrantLock();
    private volatile boolean connected = true;
    private boolean published;

    AgentSession(Process process, BufferedReader reader, BufferedWriter writer, AutoCloseable transport) {
        this.process = process;
        this.reader = reader;
        this.writer = writer;
        this.transport = transport;
    }

    Process process() { return process; }

    boolean isAlive() {
        return connected && (process == null || process.isAlive());
    }

    void publish() {
        published = true;
    }

    String exchange(String command, long timeout, TimeUnit unit) throws Exception {
        ioLock.lock();
        try {
            if (!isAlive()) throw new IOException("agent_channel_closed");
            writer.write(command);
            writer.write('\n');
            writer.flush();
            CompletableFuture<String> reply = CompletableFuture.supplyAsync(() -> {
                try {
                    return reader.readLine();
                } catch (IOException ex) {
                    throw new java.util.concurrent.CompletionException(ex);
                }
            });
            String line = reply.get(timeout, unit);
            if (line == null) throw new IOException("agent_channel_eof");
            return line;
        } catch (Exception ex) {
            // A late reply must never be consumed as the next command's result.
            connected = false;
            closeTransport();
            if (ex instanceof InterruptedException) Thread.currentThread().interrupt();
            throw ex;
        } finally {
            ioLock.unlock();
        }
    }

    void close() {
        ioLock.lock();
        try {
            // Only a newly spawned, unpublished agent belongs to this attempt.
            // A failed attachment must never shut down other classloaders' agent.
            if (process != null && !published && connected && process.isAlive()) {
                try {
                    writer.write("{\"cmd\":\"shutdown\"}\n");
                    writer.flush();
                } catch (IOException ignored) { }
            }
            connected = false;
            closeTransport();
        } finally {
            ioLock.unlock();
        }
    }

    private void closeTransport() {
        // Close the raw duplex pipe first: closing BufferedReader while another
        // thread is blocked in readLine can otherwise wait on its monitor.
        if (transport != null) {
            try { transport.close(); } catch (Exception ignored) { }
        }
        // A stdio reader may still be blocked after timeout. The JVM watchdog
        // owns agent lifetime; do not block this caller waiting for that reader.
        try { writer.close(); } catch (IOException ignored) { }
        if (transport != null) {
            try { reader.close(); } catch (IOException ignored) { }
        }
    }
}
