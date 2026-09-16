package forgevm.forge;

/**
 * Callback handle passed to ingot hook methods.
 *
 * <p>An {@code FvmCallback} is created by the injected bytecode and passed to your
 * {@code public static} hook method. It lets you inspect the target instance and
 * control whether the original method body executes.
 *
 * <h2>Control flow</h2>
 * <ul>
 *   <li>{@link #getOriginalReturnValue()} -- inspect the value already computed
 *       by the target method at a non-void {@code RETURN} injection.</li>
 *   <li>{@link #setReturnValue(Object)} -- skip the original method and return a
 *       specific value. For primitive return types, pass the boxed equivalent
 *       (e.g. {@code 20.0f} for a {@code float} method).</li>
 *   <li>{@link #cancel()} -- skip the original method for {@code void} methods.</li>
 *   <li><em>Neither called</em> -- the original method executes normally after the
 *       hook returns.</li>
 * </ul>
 *
 * <h2>Example</h2>
 * <pre>{@code
 * public static void onGetMaxRetries(FvmCallback callback) {
 *     Object target = callback.getInstance();
 *     if (target instanceof com.example.app.PremiumRetryPolicy) {
 *         callback.setReturnValue(100);  // override return value
 *     }
 *     // other instances -&gt; original method runs normally
 * }
 * }</pre>
 *
 * @see FvmIngot
 */
public final class FvmCallback {

    private final Object instance;
    private final Object[] args;
    private final Object originalReturnValue;
    private Object returnValue;
    private boolean cancelled;

    /**
     * Constructs a callback with no argument access.
     * Called by injected bytecode for methods with no parameters.
     *
     * @param instance the target method's {@code this}, or {@code null} for static methods
     */
    public FvmCallback(Object instance) {
        this(instance, null, null);
    }

    /**
     * Constructs a callback with argument access.
     * Called by injected bytecode -- not intended for direct use.
     *
     * @param instance the target method's {@code this}, or {@code null} for static methods
     * @param args the target method's arguments (reference types only; primitives are boxed)
     */
    public FvmCallback(Object instance, Object[] args) {
        this(instance, args, null);
    }

    private FvmCallback(Object instance, Object[] args, Object originalReturnValue) {
        this.instance = instance;
        this.args = args;
        this.originalReturnValue = originalReturnValue;
    }

    /**
     * Creates the callback used by injected {@code RETURN} bytecode.
     * This transformer entry point is public only because hooks may target a
     * class in any package; user hooks should not call it directly.
     */
    public static FvmCallback forReturn(Object value, Object instance, Object[] args) {
        return new FvmCallback(instance, args, value);
    }

    public static FvmCallback forReturn(boolean value, Object instance, Object[] args) {
        return forReturn(Boolean.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(byte value, Object instance, Object[] args) {
        return forReturn(Byte.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(char value, Object instance, Object[] args) {
        return forReturn(Character.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(short value, Object instance, Object[] args) {
        return forReturn(Short.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(int value, Object instance, Object[] args) {
        return forReturn(Integer.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(float value, Object instance, Object[] args) {
        return forReturn(Float.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(long value, Object instance, Object[] args) {
        return forReturn(Long.valueOf(value), instance, args);
    }

    public static FvmCallback forReturn(double value, Object instance, Object[] args) {
        return forReturn(Double.valueOf(value), instance, args);
    }

    /**
     * Returns the target object that the intercepted method was called on.
     * Cast to the expected type for conditional logic.
     *
     * @return the target instance, or {@code null} if the target method is static
     */
    public Object getInstance() {
        return instance;
    }

    /**
     * Skip the original method and return the given value instead.
     *
     * <p>For primitive return types, pass the boxed equivalent:
     * <ul>
     *   <li>{@code float} method -&gt; {@code callback.setReturnValue(20.0f)}</li>
     *   <li>{@code int} method -&gt; {@code callback.setReturnValue(42)}</li>
     *   <li>{@code boolean} method -&gt; {@code callback.setReturnValue(true)}</li>
     * </ul>
     *
     * @param value the value to return from the target method
     */
    public void setReturnValue(Object value) {
        this.returnValue = value;
        this.cancelled = true;
    }

    /**
     * Skip the original method execution without returning a value.
     * Use this for {@code void} methods; use {@link #setReturnValue(Object)} for
     * methods with a return type.
     */
    public void cancel() {
        this.cancelled = true;
    }

    /** Returns {@code true} if {@link #cancel()} or {@link #setReturnValue(Object)} was called. */
    public boolean isCancelled() {
        return cancelled;
    }

    /** Returns the value set by {@link #setReturnValue(Object)}, or {@code null} if not set. */
    public Object getReturnValue() {
        return returnValue;
    }

    /**
     * Returns the value computed by the target method before a {@code RETURN}
     * hook runs.
     *
     * <p>Primitive results are boxed. This value is independent of the
     * replacement supplied to {@link #setReturnValue(Object)}. For injection
     * points other than {@code RETURN}, and for {@code void} methods, this
     * method returns {@code null}.
     *
     * @return the target method's original return value, or {@code null}
     */
    public Object getOriginalReturnValue() {
        return originalReturnValue;
    }

    /**
     * Returns the number of arguments captured from the target method.
     *
     * @return argument count, or 0 if argument access is not available
     */
    public int argumentCount() {
        return args != null ? args.length : 0;
    }

    /**
     * Returns the target method's argument at the given index.
     *
     * @param index zero-based argument index
     * @return the argument value, or {@code null} if index is out of bounds or args not available
     */
    public Object getArgument(int index) {
        if (args == null || index < 0 || index >= args.length) return null;
        return args[index];
    }
}
