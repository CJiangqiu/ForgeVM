package forgevm.forge;

/**
 * Defines where to inject the hook within the target method's bytecode.
 *
 * <p>Basic injection points:
 * <ul>
 *   <li>{@link #HEAD} — before the first instruction</li>
 *   <li>{@link #RETURN} — before every {@code return} instruction</li>
 * </ul>
 *
 * <p>Targeted injection points (specify a target within the method body):
 * <ul>
 *   <li>{@link #INVOKE(String)} — before a call to the specified method</li>
 *   <li>{@link #FIELD_GET(String)} — before a {@code getfield}/{@code getstatic} of the specified field</li>
 *   <li>{@link #FIELD_PUT(String)} — before a {@code putfield}/{@code putstatic} of the specified field</li>
 *   <li>{@link #NEW(String)} — before a {@code new} instruction for the specified class</li>
 * </ul>
 *
 * @see FvmIngot
 */
public final class InjectPoint {

    /** Before the first instruction of the target method. */
    public static final InjectPoint HEAD = new InjectPoint("HEAD", null);

    /** Before every {@code return} instruction of the target method. */
    public static final InjectPoint RETURN = new InjectPoint("RETURN", null);

    /**
     * Before a call to the specified method within the target method's body.
     *
     * <pre>{@code
     * super("com.example.Entity", "hurt", InjectPoint.INVOKE("setHealth"));
     * }</pre>
     *
     * @param methodName the name of the method call to intercept
     */
    public static InjectPoint INVOKE(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("INVOKE target method name must not be empty");
        }
        return new InjectPoint("INVOKE", methodName);
    }

    /**
     * Before a {@code getfield}/{@code getstatic} instruction for the specified field.
     *
     * <pre>{@code
     * super("com.example.Entity", "tick", InjectPoint.FIELD_GET("health"));
     * }</pre>
     *
     * @param fieldName the name of the field access to intercept
     */
    public static InjectPoint FIELD_GET(String fieldName) {
        if (fieldName == null || fieldName.isBlank()) {
            throw new IllegalArgumentException("FIELD_GET target field name must not be empty");
        }
        return new InjectPoint("FIELD_GET", fieldName);
    }

    /**
     * Before a {@code putfield}/{@code putstatic} instruction for the specified field.
     *
     * <pre>{@code
     * super("com.example.Entity", "tick", InjectPoint.FIELD_PUT("health"));
     * }</pre>
     *
     * @param fieldName the name of the field write to intercept
     */
    public static InjectPoint FIELD_PUT(String fieldName) {
        if (fieldName == null || fieldName.isBlank()) {
            throw new IllegalArgumentException("FIELD_PUT target field name must not be empty");
        }
        return new InjectPoint("FIELD_PUT", fieldName);
    }

    /**
     * Before a {@code new} instruction for the specified class.
     *
     * <pre>{@code
     * super("com.example.Service", "process", InjectPoint.NEW("java.util.ArrayList"));
     * }</pre>
     *
     * @param className the fully qualified class name of the object creation to intercept
     */
    public static InjectPoint NEW(String className) {
        if (className == null || className.isBlank()) {
            throw new IllegalArgumentException("NEW target class name must not be empty");
        }
        return new InjectPoint("NEW", className);
    }

    private final String type;
    private final String target;

    private InjectPoint(String type, String target) {
        this.type = type;
        this.target = target;
    }

    /** Returns the injection type: HEAD, RETURN, INVOKE, FIELD_GET, FIELD_PUT, NEW. */
    public String type() { return type; }

    /** Returns the target name for parameterized points, or {@code null} for HEAD/RETURN. */
    public String target() { return target; }

    /** Returns the type name (for HEAD/RETURN) or type:target (for parameterized points). */
    public String name() {
        if (target == null) return type;
        return type + ":" + target;
    }

    @Override
    public String toString() {
        return name();
    }
}
