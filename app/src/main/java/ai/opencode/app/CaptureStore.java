package ai.opencode.app;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public final class CaptureStore {

    public static final class D {
        public final String name;
        public final int type;
        public final long first;
        volatile long last;
        volatile int count;

        D(String name, int type, long ts) {
            this.name = name;
            this.type = type;
            this.first = ts;
            this.last = ts;
            this.count = 1;
        }
    }

    private static final int MAX_DOMAINS = 4096;
    private static final ConcurrentHashMap<String, D> MAP = new ConcurrentHashMap<>();
    private static final AtomicLong TOTAL = new AtomicLong();
    private static volatile long startedAt;
    private static volatile long lastHit;

    private CaptureStore() {}

    public static void start() {
        startedAt = System.currentTimeMillis();
        lastHit = startedAt;
    }

    public static void stop() {}

    public static void clear() {
        MAP.clear();
        TOTAL.set(0);
        startedAt = 0;
        lastHit = 0;
    }

    public static long startedAt() {
        return startedAt;
    }

    public static long lastHit() {
        return lastHit;
    }

    public static long total() {
        return TOTAL.get();
    }

    public static int size() {
        return MAP.size();
    }

    public static void hit(String name, int type, long ts) {
        if (name == null) return;
        name = clean(name);
        if (name.isEmpty()) return;
        TOTAL.incrementAndGet();
        lastHit = ts;
        D d = MAP.get(name);
        if (d == null) {
            if (MAP.size() >= MAX_DOMAINS) return;
            D fresh = new D(name, type, ts);
            d = MAP.putIfAbsent(name, fresh);
            if (d == null) return;
        }
        d.last = ts;
        d.count++;
    }

    private static String clean(String s) {
        String t = s.trim();
        while (t.endsWith(".")) t = t.substring(0, t.length() - 1);
        if (t.length() > 253) t = t.substring(0, 253);
        return t.toLowerCase(Locale.US);
    }

    public static List<D> snapshot() {
        List<D> list = new ArrayList<>(MAP.values());
        Collections.sort(list, new Comparator<D>() {
            @Override public int compare(D a, D b) {
                return Long.compare(b.last, a.last);
            }
        });
        return list;
    }

    public static String typeName(int type) {
        switch (type) {
            case 1: return "A";
            case 2: return "NS";
            case 5: return "CNAME";
            case 6: return "SOA";
            case 12: return "PTR";
            case 15: return "MX";
            case 16: return "TXT";
            case 28: return "AAAA";
            case 33: return "SRV";
            case 35: return "NAPTR";
            case 64: return "SVCB";
            case 65: return "HTTPS";
            default:
                if (type == 255) return "ANY";
                return String.valueOf(type);
        }
    }

    public static String display(int max) {
        List<D> list = snapshot();
        if (list.isEmpty()) return "· nothing captured yet";
        StringBuilder b = new StringBuilder();
        int n = Math.min(max, list.size());
        for (int i = 0; i < n; i++) {
            D d = list.get(i);
            b.append(pad(typeName(d.type), 5)).append(' ')
             .append(pad(String.valueOf(d.count), 5)).append("  ")
             .append(d.name).append('\n');
        }
        if (list.size() > n) b.append("… ").append(list.size() - n).append(" more\n");
        return b.toString();
    }

    public static String dump() {
        StringBuilder b = new StringBuilder();
        b.append("# captured ").append(new Date(startedAt)).append('\n');
        b.append("# last\tcount\ttype\tname\n");
        for (D d : snapshot()) {
            b.append(d.last).append('\t')
             .append(d.count).append('\t')
             .append(typeName(d.type)).append('\t')
             .append(d.name).append('\n');
        }
        return b.toString();
    }

    private static String pad(String s, int width) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < width) b.append(' ');
        return b.toString();
    }
}
