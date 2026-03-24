package forgevm.transform;

/**
 * Callback handle passed to transformer hook methods.
 *
 * <p>An {@code FvmCallback} is created by the injected bytecode and passed to your
 * {@code public static} hook method. It lets you inspect the target instance and
 * control whether the original method body executes.
 *
 * <h2>Control flow</h2>
 * <ul>
 *   <li>{@link #setReturnValue(Object)} — skip the original method and return a
 *       specific value. For primitive return types, pass the boxed equivalent
 *       (e.g. {@code 20.0f} for a {@code float} method).</li>
 *   <li>{@link #cancel()} — skip the original method for {@code void} methods.</li>
 *   <li><em>Neither called</em> — the original method executes normally after the
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
 *     // other instances → original method runs normally
 * }
 * }</pre>
 *
 * @see FvmTransformer
 */
public final class FvmCallback {

    private final Object instance;
    private Object returnValue;
    private boolean cancelled;

    /**
     * Constructs a callback. Called by injected bytecode — not intended for direct use.
     *
     * @param instance the target method's {@code this}, or {@code null} for static methods
     */
    public FvmCallback(Object instance) {
        this.instance = instance;
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
     *   <li>{@code float} method → {@code callback.setReturnValue(20.0f)}</li>
     *   <li>{@code int} method → {@code callback.setReturnValue(42)}</li>
     *   <li>{@code boolean} method → {@code callback.setReturnValue(true)}</li>
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
}
