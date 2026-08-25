package forgevm.jvm.internal;

import forgevm.util.FvmLog;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/** Called from ForgeVM's JNI trampolines; not a public application API. */
public final class SourceResolver {
    private static final StackWalker WALKER = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
    private static final ConcurrentHashMap<String, Policy> POLICIES = new ConcurrentHashMap<>();
    private static final ThreadLocal<Boolean> WRITING_THREAD_LOG =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private SourceResolver() {}

    /** Evaluate one intercepted name against a v2 name/source policy. */
    public static boolean allow(String targetName, String encodedPolicy) {
        return evaluate(targetName, encodedPolicy, false);
    }

    /**
     * Evaluate a platform-thread start and emit a forensic record when it is
     * rejected. Called only by the JVM_StartThread trampoline so process and
     * native-load decisions are not mislabeled as thread decisions.
     */
    public static boolean allowThread(String threadName, String encodedPolicy) {
        return evaluate(threadName, encodedPolicy, true);
    }

    private static boolean evaluate(String targetName, String encodedPolicy, boolean logThreadBlock) {
        String source = "unknown";
        try {
            Policy policy = POLICIES.computeIfAbsent(encodedPolicy, SourceResolver::decode);
            source = currentSource();
            Rule matchedRule = null;
            for (Rule rule : policy.rules) {
                if ((rule.name == null || glob(rule.name, targetName == null ? "" : targetName))
                        && (rule.source == null || sourceMatches(rule.source, source))) {
                    matchedRule = rule;
                    break;
                }
            }
            boolean allowed = policy.whitelist ? matchedRule != null : matchedRule == null;
            if (!allowed && logThreadBlock) {
                logThreadBlock(targetName, source, policy, matchedRule, null);
            }
            return allowed;
        } catch (Throwable failure) {
            if (logThreadBlock) {
                logThreadBlock(targetName, source, null, null, failure);
            }
            return false;
        }
    }

    private static void logThreadBlock(String threadName, String source, Policy policy,
                                       Rule matchedRule, Throwable failure) {
        boolean armed = false;
        try {
            if (Boolean.TRUE.equals(WRITING_THREAD_LOG.get())) return;
            WRITING_THREAD_LOG.set(Boolean.TRUE);
            armed = true;
            String mode = policy == null ? "unknown" : policy.whitelist ? "whitelist" : "blacklist";
            String reason;
            if (failure != null) {
                reason = "evaluation_error:" + failure.getClass().getName();
            } else if (policy.whitelist) {
                reason = "no_whitelist_rule_matched";
            } else {
                reason = "blacklist_rule_matched";
            }
            String rule = matchedRule == null
                    ? "<none>"
                    : "name=" + printable(matchedRule.name)
                    + ",source=" + printable(matchedRule.source);
            FvmLog.warn("THREAD BLOCK | name=" + printable(threadName)
                    + " | source=" + printable(source)
                    + " | mode=" + mode
                    + " | reason=" + reason
                    + " | rule=" + rule);
        } catch (Throwable ignored) {
            // Diagnostics must never alter the fail-closed filter decision.
        } finally {
            if (armed) {
                try {
                    WRITING_THREAD_LOG.set(Boolean.FALSE);
                } catch (Throwable ignored) {
                    // Best-effort diagnostics only.
                }
            }
        }
    }

    private static String printable(String value) {
        if (value == null) return "<any>";
        String escaped = value.replace("\\", "\\\\")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
        return escaped.length() <= 2048 ? escaped : escaped.substring(0, 2048) + "...<truncated>";
    }

    /** ProcessImpl passes a Windows command line; filter its executable token. */
    public static boolean allowProcess(String commandLine, String encodedPolicy) {
        return allow(firstWindowsArgument(commandLine), encodedPolicy);
    }

    /**
     * Canonical identity of the first application caller.
     *
     * <p>A missing {@link CodeSource} is reported explicitly and is never
     * replaced with {@code ClassLoader.getResource()}: a hostile class loader
     * controls that answer and could forge a trusted JAR URL. When the direct
     * caller has no trustworthy location, ForgeVM walks outward through the
     * synchronous call chain and reports the nearest caller that does as
     * {@code initiator-class:}, {@code initiator-module:}, and
     * {@code initiator-code:}. These prefixes stay distinct so the initiator's
     * location is never misrepresented as the dynamic class's own origin.
     */
    public static String currentSource() {
        try {
            List<Class<?>> callers = WALKER.walk(stream -> stream
                    .<Class<?>>map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(type -> !isInfrastructureFrame(type))
                    .distinct()
                    .toList());
            if (callers.isEmpty()) return "unknown";

            Class<?> caller = callers.get(0);
            StringBuilder identity = new StringBuilder("class:").append(caller.getName());
            Module module = caller.getModule();
            if (module != null && module.isNamed()) {
                identity.append('\n').append("module:").append(module.getName());
            }
            URL location = codeLocation(caller);
            if (location != null) {
                identity.append('\n').append("code:").append(location.toExternalForm());
            } else {
                identity.append('\n').append("provenance:code-unavailable");
                appendNearestPhysicalInitiator(identity, callers);
            }
            return identity.toString();
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    private static void appendNearestPhysicalInitiator(StringBuilder identity, List<Class<?>> callers) {
        for (int i = 1; i < callers.size(); i++) {
            Class<?> initiator = callers.get(i);
            URL location = codeLocation(initiator);
            if (location == null) continue;
            identity.append('\n').append("initiator-class:").append(initiator.getName());
            Module module = initiator.getModule();
            if (module != null && module.isNamed()) {
                identity.append('\n').append("initiator-module:").append(module.getName());
            }
            identity.append('\n').append("initiator-code:").append(location.toExternalForm());
            return;
        }
    }

    private static URL codeLocation(Class<?> type) {
        try {
            if (type.getProtectionDomain() == null) return null;
            CodeSource codeSource = type.getProtectionDomain().getCodeSource();
            return codeSource == null ? null : codeSource.getLocation();
        } catch (SecurityException ignored) {
            return null;
        }
    }

    private static boolean isInfrastructureFrame(Class<?> type) {
        if (type == SourceResolver.class) return true;
        String name = type.getName();
        if (name.startsWith("forgevm.jvm.internal.")) return true;
        /* These bootstrap classes are the JNI bridge frames below the native
         * hooks, not the originator. Do not exclude bootstrap-loaded classes in
         * general: an attacker can deliberately place its own class there. */
        return name.equals("java.lang.Thread")
                || name.equals("java.lang.ProcessImpl")
                || name.equals("java.lang.ProcessBuilder")
                || name.equals("java.lang.Runtime")
                || name.equals("java.lang.System")
                || name.equals("java.lang.ClassLoader")
                || name.equals("jdk.internal.loader.NativeLibraries")
                || name.startsWith("jdk.internal.loader.NativeLibraries$")
                || name.equals("jdk.internal.loader.BuiltinClassLoader");
    }

    private static boolean sourceMatches(String pattern, String identity) {
        for (String token : identity.split("\\n")) {
            if (glob(pattern, token)) return true;
        }
        return false;
    }

    private static Policy decode(String encoded) {
        if (encoded == null || !encoded.startsWith("v2;") || encoded.length() < 6) {
            throw new IllegalArgumentException("unsupported policy");
        }
        char mode = encoded.charAt(3);
        if (mode != 'W' && mode != 'B') throw new IllegalArgumentException("malformed mode");
        boolean whitelist = mode == 'W';
        if (encoded.charAt(4) != ';') throw new IllegalArgumentException("malformed policy");
        String body = encoded.substring(5);
        ArrayList<Rule> rules = new ArrayList<>();
        Base64.Decoder decoder = Base64.getUrlDecoder();
        for (String item : body.split(",", -1)) {
            int dot = item.indexOf('.');
            if (dot < 0) throw new IllegalArgumentException("malformed rule");
            rules.add(new Rule(decodePart(decoder, item.substring(0, dot)),
                    decodePart(decoder, item.substring(dot + 1))));
        }
        if (rules.isEmpty()) throw new IllegalArgumentException("empty policy");
        return new Policy(whitelist, List.copyOf(rules));
    }

    private static String decodePart(Base64.Decoder decoder, String value) {
        if (value.equals("-")) return null;
        return new String(decoder.decode(value), StandardCharsets.UTF_8);
    }

    private static boolean glob(String pattern, String value) {
        String p = pattern.replace('\\', '/').toLowerCase(Locale.ROOT);
        String v = value.replace('\\', '/').toLowerCase(Locale.ROOT);
        int pi = 0, vi = 0, star = -1, retry = 0;
        while (vi < v.length()) {
            if (pi < p.length() && (p.charAt(pi) == '?' || p.charAt(pi) == v.charAt(vi))) {
                pi++; vi++;
            } else if (pi < p.length() && p.charAt(pi) == '*') {
                star = pi++;
                retry = vi;
            } else if (star >= 0) {
                pi = star + 1;
                vi = ++retry;
            } else {
                return false;
            }
        }
        while (pi < p.length() && p.charAt(pi) == '*') pi++;
        return pi == p.length();
    }

    static String firstWindowsArgument(String commandLine) {
        if (commandLine == null) return "";
        int index = 0;
        while (index < commandLine.length() && Character.isWhitespace(commandLine.charAt(index))) index++;
        StringBuilder result = new StringBuilder();
        boolean quoted = false;
        int slashes = 0;
        while (index < commandLine.length()) {
            char ch = commandLine.charAt(index++);
            if (ch == '\\') {
                slashes++;
                continue;
            }
            if (ch == '"') {
                result.append("\\".repeat(slashes / 2));
                if ((slashes & 1) != 0) result.append('"');
                else quoted = !quoted;
                slashes = 0;
                continue;
            }
            if (!quoted && Character.isWhitespace(ch)) break;
            result.append("\\".repeat(slashes)).append(ch);
            slashes = 0;
        }
        result.append("\\".repeat(slashes));
        return result.toString();
    }

    private record Rule(String name, String source) {}
    private record Policy(boolean whitelist, List<Rule> rules) {}
}
