package forgevm.transform;

/**
 * Base class for all ForgeVM bytecode transformers.
 *
 * <p>Subclass this, pass target info via constructor, and write your
 * hook method as a regular public method with an {@link FvmCallback} parameter.
 * ForgeVM will inject an {@code invokestatic} call to it at the specified point.
 *
 * <p>Example — simplest form (single method, no-arg, HEAD):
 * <pre>{@code
 * public class TickLogger extends FvmTransformer {
 *     public TickLogger() {
 *         super("com.example.Entity", "tick");
 *     }
 *
 *     public void onTick(FvmCallback callback) {
 *         System.out.println("tick called");
 *     }
 * }
 * }</pre>
 *
 * <p>Example — override return value with obfuscation candidates:
 * <pre>{@code
 * public class HealthPatch extends FvmTransformer {
 *     public HealthPatch() {
 *         super("com.example.Entity", new String[]{"getHealth", "m1234"});
 *     }
 *
 *     public void onGetHealth(FvmCallback callback) {
 *         callback.setReturnValue(20.0f);
 *     }
 * }
 * }</pre>
 */
public abstract class FvmTransformer {

    private final String targetClass;
    private final String[] targetMethodCandidates;
    private final Class<?>[] targetParams;
    private final InjectPoint injectAt;

    /**
     * @param targetClass            fully qualified name of the target class
     * @param targetMethodCandidates candidate method names, tried in order until one matches
     * @param targetParams           parameter types to distinguish overloads (empty array for no-arg)
     * @param injectAt               HEAD or RETURN
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
     * Returns the name of the user's hook method in this class.
     * TransformManager scans for the first public method that takes
     * a single {@link FvmCallback} parameter.
     */
    public String resolveHookMethodName() {
        for (java.lang.reflect.Method m : getClass().getDeclaredMethods()) {
            if (java.lang.reflect.Modifier.isPublic(m.getModifiers())) {
                Class<?>[] params = m.getParameterTypes();
                if (params.length == 1 && params[0] == FvmCallback.class) {
                    return m.getName();
                }
            }
        }
        return null;
    }

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
