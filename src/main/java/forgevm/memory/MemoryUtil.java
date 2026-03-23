package forgevm.memory;

import forgevm.core.ForgeVM;
import forgevm.core.ForgeVMException;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * ForgeVM field memory API.
 *
 * <p>Users provide a live object instance or an iterable of instances.
 * ForgeVM resolves the field offset and writes directly to JVM heap memory
 * via the native agent, bypassing JVM reflection and access restrictions.
 *
 * <p>Field descriptor format: {@code "fully.qualified.ClassName.fieldName"}
 * Example: {@code "com.example.app.UserService.active"}
 */
public final class MemoryUtil {

    private static final Unsafe UNSAFE;

    static {
        Unsafe u = null;
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            u = (Unsafe) f.get(null);
        } catch (Throwable ignored) {
        }
        UNSAFE = u;
    }

    public MemoryUtil() {
    }

    // ---- boolean ----

    public void putBooleanField(Object target, String fieldDescriptor, boolean value) {
        sendPutField(target, fieldDescriptor, new byte[]{value ? (byte) 1 : 0});
    }

    public void putBooleanField(Iterable<?> targets, String fieldDescriptor, boolean value) {
        sendPutFieldBatch(targets, fieldDescriptor, new byte[]{value ? (byte) 1 : 0});
    }

    // ---- byte ----

    public void putByteField(Object target, String fieldDescriptor, byte value) {
        sendPutField(target, fieldDescriptor, new byte[]{value});
    }

    public void putByteField(Iterable<?> targets, String fieldDescriptor, byte value) {
        sendPutFieldBatch(targets, fieldDescriptor, new byte[]{value});
    }

    // ---- char ----

    public void putCharField(Object target, String fieldDescriptor, char value) {
        sendPutField(target, fieldDescriptor, encodeShort((short) value));
    }

    public void putCharField(Iterable<?> targets, String fieldDescriptor, char value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeShort((short) value));
    }

    // ---- short ----

    public void putShortField(Object target, String fieldDescriptor, short value) {
        sendPutField(target, fieldDescriptor, encodeShort(value));
    }

    public void putShortField(Iterable<?> targets, String fieldDescriptor, short value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeShort(value));
    }

    // ---- int ----

    public void putIntField(Object target, String fieldDescriptor, int value) {
        sendPutField(target, fieldDescriptor, encodeInt(value));
    }

    public void putIntField(Iterable<?> targets, String fieldDescriptor, int value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeInt(value));
    }

    // ---- float ----

    public void putFloatField(Object target, String fieldDescriptor, float value) {
        sendPutField(target, fieldDescriptor, encodeInt(Float.floatToRawIntBits(value)));
    }

    public void putFloatField(Iterable<?> targets, String fieldDescriptor, float value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeInt(Float.floatToRawIntBits(value)));
    }

    // ---- long ----

    public void putLongField(Object target, String fieldDescriptor, long value) {
        sendPutField(target, fieldDescriptor, encodeLong(value));
    }

    public void putLongField(Iterable<?> targets, String fieldDescriptor, long value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeLong(value));
    }

    // ---- double ----

    public void putDoubleField(Object target, String fieldDescriptor, double value) {
        sendPutField(target, fieldDescriptor, encodeLong(Double.doubleToRawLongBits(value)));
    }

    public void putDoubleField(Iterable<?> targets, String fieldDescriptor, double value) {
        sendPutFieldBatch(targets, fieldDescriptor, encodeLong(Double.doubleToRawLongBits(value)));
    }

    // ---- Object reference ----

    /**
     * Write an Object reference to a field. Automatically updates the GC card table.
     */
    public void putObjectField(Object target, String fieldDescriptor, Object value) {
        requireAgent();
        String[] parts = splitDescriptor(fieldDescriptor);
        long rawOop = extractOop(target);
        byte[] valueBytes = encodeOop(value);
        String cmd = buildCmd("put_ref_field", rawOop, parts[1], parts[0], toHex(valueBytes));
        checkResponse(ForgeVM.agentSend(cmd), "put_ref_field");
    }

    /**
     * Write an Object reference to a field across all instances. Automatically updates the GC card table.
     */
    public void putObjectField(Iterable<?> targets, String fieldDescriptor, Object value) {
        requireAgent();
        String[] parts = splitDescriptor(fieldDescriptor);
        byte[] valueBytes = encodeOop(value);
        List<Long> oops = collectOops(targets);
        if (oops.isEmpty()) return;
        String cmd = buildBatchCmd("put_ref_field_batch", oops, parts[1], parts[0], toHex(valueBytes));
        checkResponse(ForgeVM.agentSend(cmd), "put_ref_field_batch");
    }

    // ============================================================
    // Internals
    // ============================================================

    private void sendPutField(Object target, String fieldDescriptor, byte[] valueBytes) {
        requireAgent();
        String[] parts = splitDescriptor(fieldDescriptor);
        long rawOop = extractOop(target);
        String cmd = buildCmd("put_field", rawOop, parts[1], parts[0], toHex(valueBytes));
        checkResponse(ForgeVM.agentSend(cmd), "put_field");
    }

    private void sendPutFieldBatch(Iterable<?> targets, String fieldDescriptor, byte[] valueBytes) {
        requireAgent();
        String[] parts = splitDescriptor(fieldDescriptor);
        List<Long> oops = collectOops(targets);
        if (oops.isEmpty()) return;
        String cmd = buildBatchCmd("put_field_batch", oops, parts[1], parts[0], toHex(valueBytes));
        checkResponse(ForgeVM.agentSend(cmd), "put_field_batch");
    }

    private static List<Long> collectOops(Iterable<?> targets) {
        List<Long> oops = new ArrayList<>();
        for (Object obj : targets) {
            if (obj != null) {
                oops.add(extractOop(obj));
            }
        }
        return oops;
    }

    private static void requireAgent() {
        if (!ForgeVM.isAgentActive()) {
            throw new ForgeVMException("agent not active - call ForgeVM.launch() first");
        }
        if (UNSAFE == null) {
            throw new ForgeVMException("unsafe not available - memory operations disabled");
        }
    }

    // -- OOP extraction --

    private static long extractOop(Object obj) {
        if (UNSAFE == null) {
            throw new ForgeVMException("unsafe not available");
        }
        Object[] arr = new Object[]{obj};
        long baseOffset = UNSAFE.arrayBaseOffset(Object[].class);
        int scale = UNSAFE.arrayIndexScale(Object[].class);
        if (scale == 4) {
            return Integer.toUnsignedLong(UNSAFE.getInt(arr, baseOffset));
        } else {
            return UNSAFE.getLong(arr, baseOffset);
        }
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

    private static byte[] encodeOop(Object value) {
        int scale = UNSAFE.arrayIndexScale(Object[].class);
        if (value == null) {
            return new byte[scale];
        }
        long oop = extractOop(value);
        if (scale == 4) {
            return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) oop).array();
        } else {
            return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(oop).array();
        }
    }

    // -- hex encoding --

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // -- descriptor parsing --

    private static String[] splitDescriptor(String descriptor) {
        int lastDot = descriptor.lastIndexOf('.');
        if (lastDot <= 0 || lastDot == descriptor.length() - 1) {
            throw new ForgeVMException("invalid_field_descriptor:" + descriptor);
        }
        return new String[]{descriptor.substring(0, lastDot), descriptor.substring(lastDot + 1)};
    }

    // -- command building --

    private static String buildCmd(String cmd, long oop, String fieldName, String className, String valueHex) {
        return "{\"cmd\":\"" + cmd + "\",\"oop\":" + Long.toUnsignedString(oop)
                + ",\"fieldName\":\"" + ForgeVM.escapeJson(fieldName)
                + "\",\"className\":\"" + ForgeVM.escapeJson(className)
                + "\",\"valueHex\":\"" + valueHex + "\"}";
    }

    private static String buildBatchCmd(String cmd, List<Long> oops, String fieldName,
                                         String className, String valueHex) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"cmd\":\"").append(cmd).append("\",\"oops\":[");
        for (int i = 0; i < oops.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(Long.toUnsignedString(oops.get(i)));
        }
        sb.append("],\"fieldName\":\"").append(ForgeVM.escapeJson(fieldName))
          .append("\",\"className\":\"").append(ForgeVM.escapeJson(className))
          .append("\",\"valueHex\":\"").append(valueHex).append("\"}");
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
