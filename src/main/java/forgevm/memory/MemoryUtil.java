package forgevm.memory;

import forgevm.core.ForgeVM;
import forgevm.core.ForgeVMException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ForgeVM field memory API — path-based, zero JVM native API dependency.
 *
 * <p>All field resolution and memory writes are performed by the native Agent
 * process via ReadProcessMemory/WriteProcessMemory. Java side only sends
 * string descriptors — no Unsafe, no reflection, no JVM API.
 *
 * <h3>Usage</h3>
 * <pre>
 * // Static field:
 * ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);
 *
 * // Instance field via path chain from a static root:
 * ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxHealth", 200);
 * </pre>
 *
 * <p>Field chain format: dot-separated field names starting from a static field.
 * The Agent navigates each reference via RPM until the final field, then writes.
 */
public final class MemoryUtil {

    public MemoryUtil() {
    }

    // ---- boolean ----

    public void putBooleanField(String className, String fieldChain, boolean value) {
        sendPutFieldPath(className, fieldChain, new byte[]{value ? (byte) 1 : 0});
    }

    // ---- byte ----

    public void putByteField(String className, String fieldChain, byte value) {
        sendPutFieldPath(className, fieldChain, new byte[]{value});
    }

    // ---- char ----

    public void putCharField(String className, String fieldChain, char value) {
        sendPutFieldPath(className, fieldChain, encodeShort((short) value));
    }

    // ---- short ----

    public void putShortField(String className, String fieldChain, short value) {
        sendPutFieldPath(className, fieldChain, encodeShort(value));
    }

    // ---- int ----

    public void putIntField(String className, String fieldChain, int value) {
        sendPutFieldPath(className, fieldChain, encodeInt(value));
    }

    // ---- float ----

    public void putFloatField(String className, String fieldChain, float value) {
        sendPutFieldPath(className, fieldChain, encodeInt(Float.floatToRawIntBits(value)));
    }

    // ---- long ----

    public void putLongField(String className, String fieldChain, long value) {
        sendPutFieldPath(className, fieldChain, encodeLong(value));
    }

    // ---- double ----

    public void putDoubleField(String className, String fieldChain, double value) {
        sendPutFieldPath(className, fieldChain, encodeLong(Double.doubleToRawLongBits(value)));
    }

    // ---- null reference ----

    /**
     * Set a reference field to null. Automatically handles GC card table update.
     */
    public void putNullField(String className, String fieldChain) {
        // Send 8 zero bytes — DLL will use correct size (4 or 8) based on compressed oops
        sendPutFieldPath(className, fieldChain, new byte[8]);
    }

    // ============================================================
    // Internals
    // ============================================================

    private static void sendPutFieldPath(String className, String fieldChain, byte[] valueBytes) {
        if (!ForgeVM.isAgentActive()) {
            throw new ForgeVMException("agent not active - call ForgeVM.launch() first");
        }
        if (className == null || className.isBlank() || fieldChain == null || fieldChain.isBlank()) {
            throw new ForgeVMException("invalid_field_path");
        }

        String cmd = "{\"cmd\":\"put_field_path\""
                + ",\"className\":\"" + ForgeVM.escapeJson(className)
                + "\",\"fieldChain\":\"" + ForgeVM.escapeJson(fieldChain)
                + "\",\"valueHex\":\"" + toHex(valueBytes) + "\"}";
        checkResponse(ForgeVM.agentSend(cmd), "put_field_path");
    }

    // -- value encoding --

    private static byte[] encodeShort(short v) {
        return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v).array();
    }

    private static byte[] encodeInt(int v) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array();
    }

    private static byte[] encodeLong(long v) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array();
    }

    // -- hex encoding --

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // -- response checking --

    private static void checkResponse(String response, String op) {
        if (response == null || response.isBlank()) {
            throw new ForgeVMException(op + "_empty_response");
        }
        String reason = "";
        int idx = response.indexOf("\"reason\":\"");
        if (idx >= 0) {
            int start = idx + 10;
            int end = response.indexOf('"', start);
            if (end > start) reason = response.substring(start, end);
        }
        if (!response.contains("\"status\":\"ok\"")) {
            throw new ForgeVMException(reason.isEmpty() ? op + "_failed" : reason);
        }
    }
}
