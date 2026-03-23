package forgevm.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class JsonUtils {
    private JsonUtils() {
    }

    public static Map<String, String> parseFlatJsonObject(String line) {
        HashMap<String, String> fields = new HashMap<>();
        if (line == null) {
            return fields;
        }

        String json = line.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return fields;
        }

        int i = 1;
        while (i < json.length() - 1) {
            i = skipWhitespace(json, i);
            if (i >= json.length() - 1 || json.charAt(i) == '}') {
                break;
            }
            if (json.charAt(i) != '"') {
                break;
            }

            int keyEnd = findStringEnd(json, i + 1);
            if (keyEnd < 0) {
                break;
            }
            String key = unescapeJson(json.substring(i + 1, keyEnd));

            i = skipWhitespace(json, keyEnd + 1);
            if (i >= json.length() || json.charAt(i) != ':') {
                break;
            }

            i = skipWhitespace(json, i + 1);
            if (i >= json.length() || json.charAt(i) != '"') {
                break;
            }

            int valueEnd = findStringEnd(json, i + 1);
            if (valueEnd < 0) {
                break;
            }
            String value = unescapeJson(json.substring(i + 1, valueEnd));
            fields.put(key, value);

            i = skipWhitespace(json, valueEnd + 1);
            if (i < json.length() && json.charAt(i) == ',') {
                i++;
            }
        }

        return fields;
    }

    public static List<Map<String, String>> parseJsonArrayOfObjects(String json, String arrayKey) {
        List<Map<String, String>> result = new ArrayList<>();
        if (json == null) {
            return result;
        }

        String pattern = "\"" + arrayKey + "\":[";
        int start = json.indexOf(pattern);
        if (start < 0) {
            return result;
        }
        start += pattern.length();

        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        int objStart = 0;

        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }
            if (c == '{') {
                if (depth == 0) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    result.add(parseFlatJsonObject(json.substring(objStart, i + 1)));
                }
            } else if (c == ']' && depth == 0) {
                break;
            }
        }

        return result;
    }

    private static int skipWhitespace(String text, int start) {
        int i = start;
        while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int findStringEnd(String text, int start) {
        boolean escaped = false;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                return i;
            }
        }
        return -1;
    }

    private static String unescapeJson(String value) {
        StringBuilder out = new StringBuilder(value.length());
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!escaped) {
                if (c == '\\') {
                    escaped = true;
                } else {
                    out.append(c);
                }
                continue;
            }

            switch (c) {
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                default -> out.append(c);
            }
            escaped = false;
        }
        if (escaped) {
            out.append('\\');
        }
        return out.toString();
    }
}
