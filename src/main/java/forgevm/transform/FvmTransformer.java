package forgevm.transform;

/**
 * Base class for ForgeVM bytecode transformers.
 *
 * <p>A transformer intercepts a target method at runtime by rewriting its bytecode
 * in the target JVM's memory. No {@code java.lang.instrument}, no JVMTI — ForgeVM
 * operates entirely out-of-process through its native Agent.
 *
 * <h2>How to use</h2>
 * <ol>
 *   <li>Extend {@code FvmTransformer} and call {@code super(targetClass, method)}
 *       to declare which method you want to intercept.</li>
 *   <li>Write a {@code public static} hook method that takes a single
 *       {@link FvmCallback} parameter. ForgeVM injects an {@code invokestatic}
 *       call to this method, so it <b>must</b> be {@code static}.</li>
 *   <li>Register via {@code ForgeVM.transformer().load(new YourTransformer())}.</li>
 *   <li>Remove via {@code ForgeVM.transformer().unload(YourTransformer.class)}
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
 * <h2>Examples</h2>
 *
 * <p><b>Simplest form</b> — intercept a no-arg method at HEAD:
 * <pre>{@code
 * public class ProcessLogger extends FvmTransformer {
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
 * public class RetryCountOverride extends FvmTransformer {
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
 * <p><b>With parameters</b> — distinguish overloads:
 * <pre>{@code
 * public class AttackBlocker extends FvmTransformer {
 *     public AttackBlocker() {
 *         super("com.example.app.CombatService", "a_71(F),applyDamage(F)");
 *     }
 *
 *     public static void onDamage(FvmCallback callback) {
 *         callback.cancel();
 *     }
 * }
 * }</pre>
 *
 * <p><b>Specify inject point</b>:
 * <pre>{@code
 * public class ShutdownGuard extends FvmTransformer {
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
public abstract class FvmTransformer {

    public static final InjectPoint HEAD = InjectPoint.HEAD;
    public static final InjectPoint RETURN = InjectPoint.RETURN;

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
    protected FvmTransformer(String targetClass, String methodDescriptor) {
        this(targetClass, methodDescriptor, InjectPoint.HEAD);
    }

    /**
     * With explicit inject point.
     * <pre>{@code
     * super("com.example.Foo", "doStuff", RETURN);
     * super("com.example.Foo", "m_123_,doStuff", RETURN);
     * }</pre>
     */
    protected FvmTransformer(String targetClass, String methodDescriptor, InjectPoint injectAt) {
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
     * Returns parsed candidate entries. Each entry is {@code [methodName, paramDesc]}.
     * paramDesc is in JVM format, e.g. {@code "(F)"} or {@code "()"} for no-arg.
     */
    public String[][] candidates() { return parsedCandidates; }

    /**
     * Returns the name of the hook method defined in this transformer subclass.
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
     * Returns a human-readable description of this transformer for logging.
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
