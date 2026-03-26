package forgevm.forge;

/**
 * Base class for ForgeVM bytecode ingots — code pieces forged into target methods.
 *
 * <p>An ingot intercepts a target method at runtime by rewriting its bytecode
 * in the target JVM's memory. No {@code java.lang.instrument}, no JVMTI — ForgeVM
 * operates entirely out-of-process through its native Agent.
 *
 * <h2>How to use</h2>
 * <ol>
 *   <li>Extend {@code FvmIngot} and call {@code super(targetClass, method)}
 *       to declare which method you want to intercept.</li>
 *   <li>Write a {@code public static} hook method that takes a single
 *       {@link FvmCallback} parameter. ForgeVM injects an {@code invokestatic}
 *       call to this method, so it <b>must</b> be {@code static}.</li>
 *   <li>Register via {@code ForgeVM.forge().load(new YourIngot())}.</li>
 *   <li>Remove via {@code ForgeVM.forge().unload(YourIngot.class)}
 *       to restore the original bytecode.</li>
 * </ol>
 *
 * <h2>Method string format</h2>
 * <ul>
 *   <li>{@code "processOrder"} — single no-arg method</li>
 *   <li>{@code "processOrder,a_42"} — multiple candidates (comma-separated, tried in order)</li>
 *   <li>{@code "attack(F)"} — method with a float parameter (JVM descriptor)</li>
 *   <li>{@code "a_56(F),applyDamage(F)"} — multiple candidates with params</li>
 *   <li>{@code "process(Ljava/lang/String;I)"} — String + int params</li>
 * </ul>
 *
 * <h2>Hook method behavior</h2>
 * <ul>
 *   <li>Call {@link FvmCallback#setReturnValue(Object)} — skip the original method
 *       and return the given value (boxed primitives for primitive return types).</li>
 *   <li>Call {@link FvmCallback#cancel()} — skip the original method (void methods).</li>
 *   <li>Call neither — the original method executes normally after the hook returns.</li>
 * </ul>
 *
 * <h2>Subclass propagation</h2>
 * <p>Override {@link #includeSubclasses()} to return {@code true} to automatically
 * forge all loaded subclasses that override the target method.
 *
 * <h2>Examples</h2>
 *
 * <p><b>Simplest form</b> — intercept a no-arg method at HEAD:
 * <pre>{@code
 * public class ProcessLogger extends FvmIngot {
 *     public ProcessLogger() {
 *         super("com.example.app.OrderService", "processOrder");
 *     }
 *
 *     public static void onProcess(FvmCallback callback) {
 *         System.out.println("processOrder called on: " + callback.getInstance());
 *     }
 * }
 * }</pre>
 *
 * <p><b>Override return value</b> — with obfuscation candidates:
 * <pre>{@code
 * public class RetryCountOverride extends FvmIngot {
 *     public RetryCountOverride() {
 *         super("com.example.app.RetryPolicy", "getMaxRetries,a_56");
 *     }
 *
 *     public static void onGetMaxRetries(FvmCallback callback) {
 *         callback.setReturnValue(10);
 *     }
 * }
 * }</pre>
 *
 * <p><b>With subclass propagation</b>:
 * <pre>{@code
 * public class HealthOverride extends FvmIngot {
 *     public HealthOverride() {
 *         super("net.minecraft.world.entity.LivingEntity", "getHealth");
 *     }
 *
 *     @Override
 *     public boolean includeSubclasses() { return true; }
 *
 *     public static void onGetHealth(FvmCallback callback) {
 *         if (customDead) callback.setReturnValue(0.0f);
 *     }
 * }
 * }</pre>
 *
 * <p><b>Specify inject point</b>:
 * <pre>{@code
 * public class ShutdownGuard extends FvmIngot {
 *     public ShutdownGuard() {
 *         super("com.example.app.AppLifecycle", "shutdown", RETURN);
 *     }
 *
 *     public static void onShutdown(FvmCallback callback) {
 *         if (shouldBlock()) callback.cancel();
 *     }
 * }
 * }</pre>
 *
 * @see FvmCallback
 * @see InjectPoint
 */
public abstract class FvmIngot {

    public static final InjectPoint HEAD = InjectPoint.HEAD;
    public static final InjectPoint RETURN = InjectPoint.RETURN;

    /** Create an INVOKE injection point. Usage: {@code super("Foo", "bar", INVOKE("targetMethod"))} */
    public static InjectPoint INVOKE(String methodName) { return InjectPoint.INVOKE(methodName); }
    /** Create a FIELD_GET injection point. Usage: {@code super("Foo", "bar", FIELD_GET("fieldName"))} */
    public static InjectPoint FIELD_GET(String fieldName) { return InjectPoint.FIELD_GET(fieldName); }
    /** Create a FIELD_PUT injection point. Usage: {@code super("Foo", "bar", FIELD_PUT("fieldName"))} */
    public static InjectPoint FIELD_PUT(String fieldName) { return InjectPoint.FIELD_PUT(fieldName); }
    /** Create a NEW injection point. Usage: {@code super("Foo", "bar", NEW("java.util.ArrayList"))} */
    public static InjectPoint NEW(String className) { return InjectPoint.NEW(className); }

    private final String targetClass;
    private final InjectPoint injectAt;
    private final String[][] parsedCandidates; // each entry: [name, paramDesc]

    /**
     * Defaults to HEAD.
     * <pre>{@code
     * super("com.example.Foo", "doStuff");
     * super("com.example.Foo", "m_123_,doStuff");
     * super("com.example.Foo", "attack(F)");
     * super("com.example.Foo", "m_123_(F),attack(F)");
     * }</pre>
     */
    protected FvmIngot(String targetClass, String methodDescriptor) {
        this(targetClass, methodDescriptor, InjectPoint.HEAD);
    }

    /**
     * With explicit inject point.
     * <pre>{@code
     * super("com.example.Foo", "doStuff", RETURN);
     * super("com.example.Foo", "m_123_,doStuff", RETURN);
     * }</pre>
     */
    protected FvmIngot(String targetClass, String methodDescriptor, InjectPoint injectAt) {
        if (targetClass == null || targetClass.isBlank()) {
            throw new IllegalArgumentException("targetClass must not be empty");
        }
        if (methodDescriptor == null || methodDescriptor.isBlank()) {
            throw new IllegalArgumentException("methodDescriptor must not be empty");
        }
        if (injectAt == null) {
            throw new IllegalArgumentException("injectAt must not be null");
        }
        this.targetClass = targetClass;
        this.injectAt = injectAt;
        this.parsedCandidates = parseMethodDescriptor(methodDescriptor);
    }

    public String targetClass() { return targetClass; }
    public InjectPoint injectAt() { return injectAt; }

    /**
     * Whether to automatically forge all loaded subclasses that override the target method.
     * Default is {@code false} — only the specified class is forged.
     *
     * <p>Override to return {@code true} to enable subclass propagation:
     * <pre>{@code
     * @Override
     * public boolean includeSubclasses() { return true; }
     * }</pre>
     */
    public boolean includeSubclasses() { return false; }

    /**
     * Returns parsed candidate entries. Each entry is {@code [methodName, paramDesc]}.
     * paramDesc is in JVM format, e.g. {@code "(F)"} or {@code "()"} for no-arg.
     */
    public String[][] candidates() { return parsedCandidates; }

    /**
     * Returns the name of the hook method defined in this ingot subclass.
     *
     * <p>Scans for the first {@code public static} method that takes a single
     * {@link FvmCallback} parameter. The method must be {@code static} because
     * ForgeVM injects an {@code invokestatic} bytecode to call it.
     *
     * @return the hook method name, or {@code null} if none found
     */
    public String resolveHookMethodName() {
        for (java.lang.reflect.Method m : getClass().getDeclaredMethods()) {
            int mod = m.getModifiers();
            if (java.lang.reflect.Modifier.isPublic(mod)
                    && java.lang.reflect.Modifier.isStatic(mod)) {
                Class<?>[] params = m.getParameterTypes();
                if (params.length == 1 && params[0] == FvmCallback.class) {
                    return m.getName();
                }
            }
        }
        return null;
    }

    /**
     * Returns a human-readable description of this ingot for logging.
     */
    public final String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append(targetClass).append('.').append(parsedCandidates[0][0]);
        if (parsedCandidates.length > 1) {
            sb.append(" (+").append(parsedCandidates.length - 1).append(" candidates)");
        }
        sb.append(parsedCandidates[0][1]);
        sb.append(" @ ").append(injectAt.name());
        String hookName = resolveHookMethodName();
        sb.append(" -> ").append(getClass().getName());
        if (hookName != null) sb.append('.').append(hookName).append("()");
        if (includeSubclasses()) sb.append(" [+subclasses]");
        return sb.toString();
    }

    // -- parsing --

    /**
     * Parses "a_56(F),applyDamage(F)" into [["a_56","(F)"], ["applyDamage","(F)"]]
     * Parses "processOrder" into [["processOrder","()"]]
     */
    private static String[][] parseMethodDescriptor(String descriptor) {
        String[] parts = descriptor.split(",");
        String[][] result = new String[parts.length][2];
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            int parenIdx = part.indexOf('(');
            if (parenIdx >= 0) {
                result[i][0] = part.substring(0, parenIdx);
                String paramPart = part.substring(parenIdx);
                if (!paramPart.endsWith(")")) {
                    paramPart = paramPart + ")";
                }
                result[i][1] = paramPart;
            } else {
                result[i][0] = part;
                result[i][1] = "()";
            }
        }
        return result;
    }
}
