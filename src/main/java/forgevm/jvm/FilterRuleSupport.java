package forgevm.jvm;

import java.util.ArrayList;
import java.util.List;

final class FilterRuleSupport {
    private FilterRuleSupport() {}

    static List<InterceptionRule> names(String[] patterns) {
        validatePatterns(patterns);
        ArrayList<InterceptionRule> rules = new ArrayList<>(patterns.length);
        for (String pattern : patterns) rules.add(InterceptionRule.Name(pattern));
        return List.copyOf(rules);
    }

    static List<String> patterns(String[] patterns) {
        validatePatterns(patterns);
        return List.of(patterns.clone());
    }

    static List<InterceptionRule> sources(String[] patterns) {
        validatePatterns(patterns);
        ArrayList<InterceptionRule> rules = new ArrayList<>(patterns.length);
        for (String pattern : patterns) rules.add(InterceptionRule.Source(pattern));
        return List.copyOf(rules);
    }

    static List<InterceptionRule> explicit(InterceptionRule first, InterceptionRule[] rest) {
        if (first == null) throw new IllegalArgumentException("rule must not be null");
        ArrayList<InterceptionRule> rules = new ArrayList<>((rest == null ? 0 : rest.length) + 1);
        rules.add(first);
        if (rest != null) {
            for (InterceptionRule rule : rest) {
                if (rule == null) throw new IllegalArgumentException("rule must not be null");
                rules.add(rule);
            }
        }
        return List.copyOf(rules);
    }

    static List<String> legacyPatterns(List<InterceptionRule> rules) {
        ArrayList<String> patterns = new ArrayList<>(rules.size());
        for (InterceptionRule rule : rules) {
            String value = rule.namePattern() != null ? rule.namePattern() : rule.sourcePattern();
            patterns.add(value);
        }
        return List.copyOf(patterns);
    }

    private static void validatePatterns(String[] patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("patterns must not be empty");
        }
        for (String pattern : patterns) {
            if (pattern == null || pattern.isBlank()) {
                throw new IllegalArgumentException("pattern must not be null or blank");
            }
        }
    }
}
