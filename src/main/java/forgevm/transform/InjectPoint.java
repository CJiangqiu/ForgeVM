package forgevm.transform;

public enum InjectPoint {
    /** Before the first instruction of the target method. */
    HEAD,
    /** Before every return instruction of the target method. */
    RETURN
}
