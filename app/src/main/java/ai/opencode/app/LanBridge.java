package ai.opencode.app;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Loopback HTTP bridge that lets the agent ask the ANDROID side for a LAN
 * scan. The agent shell (Debian guest or native/Alpine) shares this app's
 * network namespace, so 127.0.0.1 is reachable; it can then run
 *
 *     curl -fsS "$(cat ~/.lan-bridge)"
 *
 * and receive {@link LanDiscovery}'s JSON. The URL carries a per-install
 * token: another app on the device cannot read our private prefs, so it
 * cannot forge the scan request even if it finds the port.
 *
 * This intentionally does NOT try to become root or open raw sockets. The
 * scan is the same non-privileged TCP connect scan the diagnostics screen
 * runs; ARP/SYN scanning still needs root/adb.
 */
public final class LanBridge {

    private LanBridge() {}

    /** Preference key backing the Settings → "LAN discovery bridge" switch. */
    public static final String PREF = "lan_bridge";

    /** Where the agent finds the URL+token. Written into the guest home and
     *  the opencode home; whichever the shell has, it can read it. */
    public static final String HELP_FILE = ".lan-bridge";

    /** Last scan, for agents that would rather read a file than run curl. */
    public static final String LAST_FILE = ".lan-last.json";

    private static volatile int port = -1;
    private static volatile ServerSocket acceptor;

    private static final Object scanLock = new Object();
    private static volatile String lastJson;
    private static volatile long lastAt;
    private static final long CACHE_MS = 5_000;

    private static final AtomicInteger conns = new AtomicInteger();
    private static final int MAX_CONNS = 8;

    /** Start once; returns the port, or -1 when disabled/unavailable. */
    public static int ensureStarted(Context c) {
        if (!enabled(c)) return -1;
        appContext = c.getApplicationContext();
        if (port > 0 && acceptor != null && !acceptor.isClosed()) {
            writeHelp(c);
            return port;
        }
        synchronized (LanBridge.class) {
            if (!enabled(c)) return -1;
            if (port > 0 && acceptor != null && !acceptor.isClosed()) {
                writeHelp(c);
                return port;
            }
            try {
                ServerSocket ss = new ServerSocket(0, 16,
                        InetAddress.getByName("127.0.0.1"));
                ss.setReuseAddress(true);
                acceptor = ss;
                port = ss.getLocalPort();
                Thread t = new Thread(() -> acceptLoop(ss), "oc-lan-accept");
                t.setDaemon(true);
                t.start();
                writeHelp(c);
                return port;
            } catch (Exception e) {
                port = -1;
                return -1;
            }
        }
    }

    /** The full URL (with token) the agent should GET, or null. */
    public static String url(Context c) {
        int p = ensureStarted(c);
        if (p <= 0) return null;
        return "http://127.0.0.1:" + p + "/lan?t=" + token(c);
    }

    public static boolean enabled(Context c) {
        try {
            return c.getSharedPreferences("oc", Context.MODE_PRIVATE)
                    .getBoolean(PREF, true);
        } catch (Exception e) {
            return false;
        }
    }

    public static int port() { return port; }

    // --------------------------------------------------------------- token

    static String token(Context c) {
        try {
            String t = c.getSharedPreferences("oc", Context.MODE_PRIVATE)
                    .getString("lan_bridge_token", null);
            if (t != null && t.length() >= 16) return t;
            byte[] raw = new byte[16];
            new SecureRandom().nextBytes(raw);
            StringBuilder b = new StringBuilder(raw.length * 2);
            for (byte v : raw) b.append(String.format("%02x", v & 0xFF));
            String made = b.toString();
            c.getSharedPreferences("oc", Context.MODE_PRIVATE).edit()
                    .putString("lan_bridge_token", made).apply();
            return made;
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean tokenMatches(String given, String expected) {
        if (given == null || expected == null || expected.isEmpty()) return false;
        return MessageDigest.isEqual(given.getBytes(),
                expected.getBytes());
    }

    // --------------------------------------------------------------- server

    private static void acceptLoop(ServerSocket ss) {
        while (true) {
            try {
                Socket client = ss.accept();
                if (conns.get() >= MAX_CONNS) {
                    try { client.close(); } catch (Exception ignored) {}
                    continue;
                }
                conns.incrementAndGet();
                Thread t = new Thread(() -> {
                    try { handle(client); }
                    finally { conns.decrementAndGet(); }
                }, "oc-lan");
                t.setDaemon(true);
                t.start();
            } catch (Exception e) {
                if (ss.isClosed()) return;
                try { Thread.sleep(200); } catch (InterruptedException ie) { return; }
            }
        }
    }

    private static void handle(Socket client) {
        try {
            client.setSoTimeout(10_000);
            InputStream in = client.getInputStream();
            String reqLine = readLine(in);
            // Drain headers (we need none of them).
            String l;
            while ((l = readLine(in)) != null && !l.isEmpty()) { /* ignore */ }
            client.setSoTimeout(0);

            if (reqLine == null) { client.close(); return; }
            String[] parts = reqLine.split(" ");
            if (parts.length < 2 || !"GET".equalsIgnoreCase(parts[0])) {
                send(client, 405, "Method Not Allowed", "text/plain",
                        "GET only\n".getBytes("UTF-8"));
                return;
            }
            String target = parts[1];
            String path = target;
            String query = "";
            int q = target.indexOf('?');
            if (q >= 0) { path = target.substring(0, q); query = target.substring(q + 1); }

            // Check the switch on every request so turning it off takes
            // effect without restarting the process.
            Context ctx = appContext;
            if (ctx == null || !enabled(ctx)) {
                send(client, 403, "Forbidden", "text/plain",
                        "LAN bridge disabled\n".getBytes("UTF-8"));
                return;
            }
            if (!"/lan".equals(path)) {
                send(client, 404, "Not Found", "text/plain",
                        "GET /lan?t=<token>\n".getBytes("UTF-8"));
                return;
            }
            String given = queryParam(query, "t");
            if (!tokenMatches(given, token(ctx))) {
                send(client, 403, "Forbidden", "text/plain",
                        "bad token\n".getBytes("UTF-8"));
                return;
            }

            int[] ports = parsePorts(queryParam(query, "ports"));
            int timeout = parsePositiveInt(queryParam(query, "timeout"),
                    LanScan.DEFAULT_TIMEOUT_MS);
            long now = System.currentTimeMillis();
            String json;
            if (lastJson != null && now - lastAt < CACHE_MS) {
                json = lastJson;
            } else {
                synchronized (scanLock) {
                    now = System.currentTimeMillis();
                    if (lastJson == null || now - lastAt >= CACHE_MS) {
                        json = LanDiscovery.scanJson(ctx, ports, timeout);
                        lastJson = json;
                        lastAt = now;
                        writeLast(ctx, json);
                    } else {
                        json = lastJson;
                    }
                }
            }
            send(client, 200, "OK", "application/json; charset=utf-8",
                    json.getBytes("UTF-8"));
        } catch (Exception e) {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    /** Set by ensureStarted so request handlers can reach the app context
     *  without holding a static Activity (which would leak it). */
    private static volatile Context appContext;

    private static void send(Socket client, int code, String reason,
                             String type, byte[] body) {
        try {
            OutputStream o = client.getOutputStream();
            String head = "HTTP/1.1 " + code + " " + reason + "\r\n"
                    + "Content-Type: " + type + "\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Connection: close\r\n\r\n";
            o.write(head.getBytes("UTF-8"));
            o.write(body);
            o.flush();
        } catch (Exception ignored) {
        } finally {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    private static String queryParam(String query, String key) {
        if (query == null || query.isEmpty()) return null;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            if (k.equals(key)) {
                try {
                    return java.net.URLDecoder.decode(v, "UTF-8");
                } catch (Exception e) {
                    return v;
                }
            }
        }
        return null;
    }

    private static int[] parsePorts(String csv) {
        if (csv == null || csv.trim().isEmpty()) return LanScan.DEFAULT_PORTS;
        String[] chunks = csv.split(",");
        int[] tmp = new int[chunks.length];
        int n = 0;
        for (String chunk : chunks) {
            try {
                int p = Integer.parseInt(chunk.trim());
                if (p > 0 && p <= 65535) tmp[n++] = p;
            } catch (NumberFormatException ignored) {}
        }
        if (n == 0) return LanScan.DEFAULT_PORTS;
        int[] out = new int[n];
        System.arraycopy(tmp, 0, out, 0, n);
        return out;
    }

    private static int parsePositiveInt(String s, int fallback) {
        if (s == null) return fallback;
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 ? v : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder b = new StringBuilder(80);
        int prev = -1;
        while (true) {
            int i = in.read();
            if (i < 0) return b.length() == 0 ? null : b.toString();
            if (prev == '\r' && i == '\n') return b.substring(0, b.length() - 1);
            b.append((char) i);
            prev = i;
            if (b.length() > 8192) throw new IOException("header line too long");
        }
    }

    // ------------------------------------------------------------ help file

    /** Write the URL+token (and the last scan, if any) where the agent's
     *  shell can read it. Best-effort and idempotent. */
    public static void writeHelp(Context c) {
        appContext = c.getApplicationContext();
        String u = "http://127.0.0.1:" + port + "/lan?t=" + token(c) + "\n";
        for (File home : homes(c)) {
            writeIfDifferent(new File(home, HELP_FILE), u);
            if (lastJson != null)
                writeIfDifferent(new File(home, LAST_FILE), lastJson);
        }
    }

    /** Record the latest scan where the agent can read it as a file. */
    public static void writeLast(Context c, String json) {
        for (File home : homes(c)) writeIfDifferent(new File(home, LAST_FILE), json);
    }

    /** Both places a shell may land: the opencode $HOME and the Debian
     *  rootfs /root (present only after the guest is installed). */
    private static java.util.List<File> homes(Context c) {
        java.util.List<File> out = new java.util.ArrayList<>(2);
        try { out.add(Binaries.homeDir(c)); } catch (Exception ignored) {}
        try {
            File root = Debian.rootfsDir(c);
            File guestRoot = new File(root, "root");
            if (guestRoot.isDirectory()) out.add(guestRoot);
        } catch (Exception ignored) {}
        return out;
    }

    private static void writeIfDifferent(File f, String text) {
        try {
            File dir = f.getParentFile();
            if (dir != null && !dir.isDirectory()) dir.mkdirs();
            byte[] body = text.getBytes("UTF-8");
            if (f.isFile()) {
                long len = f.length();
                if (len == body.length) {
                    byte[] old = new byte[body.length];
                    java.io.FileInputStream in = new java.io.FileInputStream(f);
                    try {
                        int off = 0, n;
                        while (off < old.length
                                && (n = in.read(old, off, old.length - off)) > 0)
                            off += n;
                        if (off == old.length && java.util.Arrays.equals(old, body))
                            return;
                    } finally {
                        in.close();
                    }
                }
            }
            File tmp = new File(f.getPath() + ".part");
            try (FileOutputStream o = new FileOutputStream(tmp)) { o.write(body); }
            if (f.exists()) f.delete();
            if (!tmp.renameTo(f)) {
                try (FileOutputStream o = new FileOutputStream(f)) { o.write(body); }
                tmp.delete();
            }
        } catch (Exception ignored) {}
    }
}
