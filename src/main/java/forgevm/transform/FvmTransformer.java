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
 *   <li>Extend {@code FvmTransformer} and call the appropriate {@code super(...)}
 *       constructor to declare which method you want to intercept.</li>
 *   <li>Write a {@code public static} hook method that takes a single
 *       {@link FvmCallback} parameter. ForgeVM injects an {@code invokestatic}
 *       call to this method, so it <b>must</b> be {@code static}.</li>
 *   <li>Register via {@code ForgeVM.transformer().load(new YourTransformer())}.</li>
 *   <li>Remove via {@code ForgeVM.transformer().unload(YourTransformer.class)}
 *       to restore the original bytecode.</li>
 * </ol>
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
 * public class TickLogger extends FvmTransformer {
 *     public TickLogger() {
 *         super("com.example.engine.GameLoop", "tick");
 *     }
 *
 *     public static void onTick(FvmCallback callback) {
 *         System.out.println("tick called on: " + callback.getInstance());
 *     }
 * }
 * }</pre>
 *
 * <p><b>Override return value</b> — with obfuscation candidates:
 * <pre>{@code
 * public class HealthOverride extends FvmTransformer {
 *     public HealthOverride() {
 *         super("com.example.entity.LivingEntity",
 *               new String[]{"getHealth", "m_1234"});
 *     }
 *
 *     public static void onGetHealth(FvmCallback callback) {
 *         callback.setReturnValue(20.0f);
 *     }
 * }
 * }</pre>
 *
 * <p><b>Conditional logic</b> — only affect certain instances:
 * <pre>{@code
 * public class PlayerHealthOnly extends FvmTransformer {
 *     public PlayerHealthOnly() {
 *         super("com.example.entity.LivingEntity",
 *               new String[]{"getHealth", "m_1234"});
 *     }
 *
 *     public static void onGetHealth(FvmCallback callback) {
 *         if (callback.getInstance() instanceof com.example.entity.Player) {
 *             callback.setReturnValue(20.0f);
 *         }
 *         // other instances → original method runs normally
 *     }
 * }
 * }</pre>
 *
 * <p><b>Cancel a void method</b>:
 * <pre>{@code
 * public class TickGuard extends FvmTransformer {
 *     public TickGuard() {
 *         super("com.example.engine.GameLoop", "tick", InjectPoint.HEAD);
 *     }
 *
 *     public static void onTick(FvmCallback callback) {
 *         if (shouldBlock()) {
 *             callback.cancel();  // original tick() is skipped
 *         }
 *     }
 * }
 * }</pre>
 *
 * <h2>Constructor variants</h2>
 * <pre>{@code
 * // Single method, no-arg, HEAD (simplest)
 * super("com.example.Foo", "bar");
 *
 * // Multiple candidate names (obfuscation support)
 * super("com.example.Foo", new String[]{"bar", "a_42"});
 *
 * // Specify inject point
 * super("com.example.Foo", "bar", InjectPoint.RETURN);
 *
 * // With parameter types (distinguish overloads)
 * super("com.example.Foo", "bar", new Class<?>[]{float.class}, InjectPoint.HEAD);
 * }</pre>
 *
 * @see FvmCallback
 * @see InjectPoint
 */
public abstract class FvmTransformer {

    private final String targetClass;
    private final String[] targetMethodCandidates;
    private final Class<?>[] targetParams;
    private final InjectPoint injectAt;

    /**
     * Full constructor.
     *
     * @param targetClass            fully qualified name of the target class
     * @param targetMethodCandidates candidate method names, tried in order until one matches
     * @param targetParams           parameter types to distinguish overloads (empty array for no-arg)
     * @param injectAt               where to inject: {@link InjectPoint#HEAD} or {@link InjectPoint#RETURN}
     */
    protected FvmTransformer(String targetClass, String[] targetMethodCandidates,
                             Class<?>[] targetParams, InjectPoint injectAt) {
        if (targetClass == null || targetClass.isBlank()) {
            throw new IllegalArgumentException("targetClass must not be empty");
        }
        if (targetMethodCandidates == null || targetMethodCandidates.length == 0) {
            throw new IllegalArgumentException("targetMethodCandidates must not be empty");
        }
        if (targetParams == null) {
            throw new IllegalArgumentException("targetParams must not be null (use empty array for no-arg)");
        }
        if (injectAt == null) {
            throw new IllegalArgumentException("injectAt must not be null");
        }
        this.targetClass = targetClass;
        this.targetMethodCandidates = targetMethodCandidates;
        this.targetParams = targetParams;
        this.injectAt = injectAt;
    }

    /** Single method name, with params and inject point. */
    protected FvmTransformer(String targetClass, String targetMethod,
                             Class<?>[] targetParams, InjectPoint injectAt) {
        this(targetClass, new String[]{targetMethod}, targetParams, injectAt);
    }

    /** Multiple candidates + inject point, no-arg target method. */
    protected FvmTransformer(String targetClass, String[] targetMethodCandidates,
                             InjectPoint injectAt) {
        this(targetClass, targetMethodCandidates, new Class<?>[0], injectAt);
    }

    /** Single method name + inject point, no-arg target method. */
    protected FvmTransformer(String targetClass, String targetMethod,
                             InjectPoint injectAt) {
        this(targetClass, new String[]{targetMethod}, new Class<?>[0], injectAt);
    }

    /** Multiple candidates, no-arg, defaults to HEAD. */
    protected FvmTransformer(String targetClass, String[] targetMethodCandidates) {
        this(targetClass, targetMethodCandidates, new Class<?>[0], InjectPoint.HEAD);
    }

    /** Single method name, no-arg, defaults to HEAD. Simplest form. */
    protected FvmTransformer(String targetClass, String targetMethod) {
        this(targetClass, new String[]{targetMethod}, new Class<?>[0], InjectPoint.HEAD);
    }

    public String targetClass() { return targetClass; }
    public String[] targetMethodCandidates() { return targetMethodCandidates; }
    public Class<?>[] targetParams() { return targetParams; }
    public InjectPoint injectAt() { return injectAt; }

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
     *
     * <p>Format: {@code com.example.Foo.bar (+N candidates)(params) @ HEAD -> hook.Class.method()}
     */
    public final String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append(targetClass).append('.').append(targetMethodCandidates[0]);
        if (targetMethodCandidates.length > 1) {
            sb.append(" (+").append(targetMethodCandidates.length - 1).append(" candidates)");
        }
        sb.append('(');
        for (int i = 0; i < targetParams.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(targetParams[i].getSimpleName());
        }
        sb.append(") @ ").append(injectAt.name());
        String hookName = resolveHookMethodName();
        sb.append(" -> ").append(getClass().getName());
        if (hookName != null) sb.append('.').append(hookName).append("()");
        return sb.toString();
    }
}
