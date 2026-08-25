package forgevm.jvm;

import java.util.Objects;

/**
 * One interception rule with independent target-name and request-source selectors.
 * A non-null selector must match; when both are present they are combined with AND.
 *
 * <p>Source strings are caller-identity tokens emitted by ForgeVM, for example
 * {@code class:com.example.Worker}, {@code code:file:/app/plugin.jar},
 * {@code initiator-code:file:/app/plugin.jar},
 * {@code provenance:code-unavailable}, and {@code module:C:/app/native.dll}.
 * A {@code code:} token is emitted only when the VM supplies a trustworthy
 * {@code CodeSource} for the direct caller. When that is unavailable,
 * {@code initiator-code:} may identify the nearest synchronous caller that
 * still has a trustworthy physical origin. See each filter for the tokens
 * available at its interception boundary.</p>
 */
public final class InterceptionRule {
    private final String namePattern;
    private final String sourcePattern;

    private InterceptionRule(String namePattern, String sourcePattern) {
        this.namePattern = validate(namePattern, "namePattern");
        this.sourcePattern = validate(sourcePattern, "sourcePattern");
        if (this.namePattern == null && this.sourcePattern == null) {
            throw new IllegalArgumentException("a rule requires a name or source pattern");
        }
    }

    /** Match only the intercepted target name/path. */
    public static InterceptionRule Name(String pattern) {
        return new InterceptionRule(pattern, null);
    }

    /** Match only a reported request-source identity token. */
    public static InterceptionRule Source(String pattern) {
        return new InterceptionRule(null, pattern);
    }

    /** Match when both target name/path and a request-source identity token match. */
    public static InterceptionRule NameAndSource(String namePattern, String sourcePattern) {
        return new InterceptionRule(namePattern, sourcePattern);
    }

    public String namePattern() { return namePattern; }
    public String sourcePattern() { return sourcePattern; }

    private static String validate(String value, String label) {
        if (value == null) return null;
        if (value.isBlank()) throw new IllegalArgumentException(label + " must not be blank");
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\t') >= 0) {
            throw new IllegalArgumentException(label + " must be a single token");
        }
        return value;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof InterceptionRule rule)) return false;
        return Objects.equals(namePattern, rule.namePattern)
                && Objects.equals(sourcePattern, rule.sourcePattern);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namePattern, sourcePattern);
    }

    @Override
    public String toString() {
        return "InterceptionRule[name=" + namePattern + ", source=" + sourcePattern + "]";
    }
}
