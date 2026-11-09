package ai.opencode.app;

import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Parsing of the {@code /lan} query string: port lists/ranges, scan presets
 * and boolean flags. Pure Java so the bridge's input handling is unit-testable
 * without an Android runtime.
 */
public final class LanQuery {

    private LanQuery() {}

    /** Hard ceiling on ports per request. A /24 × 1024 ports is already a
     *  heavy scan; anything larger is truncated rather than allowing a
     *  request to hammer the segment for many minutes. */
    public static final int MAX_PORTS = 1024;

    public static final int[] QUICK = LanScan.DEFAULT_PORTS;

    public static final int[] COMMON = {
            21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 515, 554, 631,
            993, 995, 1433, 2049, 3306, 3389, 5000, 5432, 5555, 5900, 6379,
            8000, 8080, 8443, 8888, 9100
    };

    public static final int[] MEDIA = {
            80, 443, 554, 1900, 5000, 7000, 8008, 8080, 8443, 9000, 9100,
            32400, 32469
    };

    public static final int[] IOT = {
            80, 443, 1883, 5000, 8080, 8443, 8883, 9100, 49152
    };

    /** Named preset, or null when the name is unknown. */
    public static int[] profile(String name) {
        if (name == null) return null;
        String n = name.trim().toLowerCase(Locale.US);
        if (n.equals("quick") || n.equals("default")) return QUICK;
        if (n.equals("common")) return COMMON;
        if (n.equals("media")) return MEDIA;
        if (n.equals("iot")) return IOT;
        return null;
    }

    /**
     * Parse a comma-separated list of ports and ranges ("22,80,8000-8010").
     * Invalid tokens are ignored; an empty/blank/all-invalid input yields the
     * default port set. The result is sorted, de-duplicated and capped at
     * {@link #MAX_PORTS}.
     */
    public static int[] parsePorts(String csv) {
        if (csv == null || csv.trim().isEmpty()) return LanScan.DEFAULT_PORTS;
        Set<Integer> set = new TreeSet<>();
        for (String chunk : csv.split(",")) {
            String token = chunk.trim();
            if (token.isEmpty()) continue;
            int dash = token.indexOf('-');
            try {
                if (dash > 0 && dash < token.length() - 1) {
                    int lo = Integer.parseInt(token.substring(0, dash).trim());
                    int hi = Integer.parseInt(token.substring(dash + 1).trim());
                    if (lo > hi) { int t = lo; lo = hi; hi = t; }
                    if (lo < 1) lo = 1;
                    if (hi > 65535) hi = 65535;
                    for (int p = lo; p <= hi && set.size() < MAX_PORTS; p++) {
                        set.add(p);
                    }
                } else {
                    int p = Integer.parseInt(token);
                    if (p >= 1 && p <= 65535) set.add(p);
                }
            } catch (NumberFormatException ignored) {
                // Skip the malformed token; keep the rest.
            }
        }
        if (set.isEmpty()) return LanScan.DEFAULT_PORTS;
        int[] out = new int[set.size()];
        int i = 0;
        for (Integer p : set) out[i++] = p;
        return out;
    }

    /** Accepts 1/0, true/false, yes/no, on/off (case-insensitive). */
    public static boolean parseBool(String value, boolean fallback) {
        if (value == null) return fallback;
        String v = value.trim().toLowerCase(Locale.US);
        if (v.equals("1") || v.equals("true") || v.equals("yes")
                || v.equals("on")) return true;
        if (v.equals("0") || v.equals("false") || v.equals("no")
                || v.equals("off")) return false;
        return fallback;
    }

    public static int parsePositiveInt(String value, int fallback) {
        if (value == null) return fallback;
        try {
            int v = Integer.parseInt(value.trim());
            return v > 0 ? v : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
