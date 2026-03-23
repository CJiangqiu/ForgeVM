package forgevm.transform;

/**
 * Passed to transformer methods to control the target method's behavior.
 *
 * <p>{@link #getInstance()} returns the target object ({@code this} of the
 * target method), allowing conditional logic based on which instance triggered the call.
 *
 * <p>Call {@link #setReturnValue(Object)} to make the target method
 * return a specific value and skip the original body.
 * Call {@link #cancel()} to skip the original body for void methods.
 * If neither is called, the target method executes normally.
 */
public final class FvmCallback {

    private final Object instance;
    private Object returnValue;
    private boolean cancelled;

    /**
     * @param instance the target method's {@code this}, or null if static
     */
    public FvmCallback(Object instance) {
        this.instance = instance;
    }

    /**
     * Returns the target object that the method was called on.
     * Cast to the expected type for conditional logic.
     *
     * @return the target instance, or null if the target method is static
     */
    public Object getInstance() {
        return instance;
    }

    /**
     * Cancel the original method and return the given value.
     * For primitive return types, pass the boxed equivalent
     * (e.g. {@code 20.0f} for a float method).
     */
    public void setReturnValue(Object value) {
        this.returnValue = value;
        this.cancelled = true;
    }

    /**
     * Cancel the original method execution.
     * For void methods, use this instead of {@link #setReturnValue(Object)}.
     */
    public void cancel() {
        this.cancelled = true;
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public Object getReturnValue() {
        return returnValue;
    }
}
