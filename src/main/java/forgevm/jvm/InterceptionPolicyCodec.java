package forgevm.jvm;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/** Internal wire codec shared with the in-process source resolver. */
public final class InterceptionPolicyCodec {
    private InterceptionPolicyCodec() {}

    public static String encode(String mode, List<InterceptionRule> rules) {
        if (mode == null || rules == null || rules.isEmpty()) {
            throw new IllegalArgumentException("mode and rules are required");
        }
        final char wireMode;
        if (mode.equalsIgnoreCase("whitelist")) wireMode = 'W';
        else if (mode.equalsIgnoreCase("blacklist")) wireMode = 'B';
        else throw new IllegalArgumentException("unsupported filter mode: " + mode);
        StringBuilder out = new StringBuilder("v2;")
                .append(wireMode)
                .append(';');
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        for (int i = 0; i < rules.size(); i++) {
            if (i > 0) out.append(',');
            InterceptionRule rule = rules.get(i);
            append(out, encoder, rule.namePattern());
            out.append('.');
            append(out, encoder, rule.sourcePattern());
        }
        return out.toString();
    }

    private static void append(StringBuilder out, Base64.Encoder encoder, String value) {
        if (value == null) {
            out.append('-');
        } else {
            out.append(encoder.encodeToString(value.getBytes(StandardCharsets.UTF_8)));
        }
    }
}
