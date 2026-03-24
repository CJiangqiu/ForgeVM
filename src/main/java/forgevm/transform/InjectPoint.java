package forgevm.transform;

/**
 * Where to inject the hook call within the target method's bytecode.
 *
 * @see FvmTransformer
 */
public enum InjectPoint {
    /**
     * Before the first instruction of the target method.
     * The hook runs before any of the original method body executes.
     */
    HEAD,

    /**
     * Before every {@code return} instruction of the target method.
     * The hook runs just before the method would return to its caller.
     */
    RETURN
}
