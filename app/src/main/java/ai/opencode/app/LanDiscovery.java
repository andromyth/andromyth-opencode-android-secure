package ai.opencode.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Android-side glue between the platform's interface/link data and the
 * pure {@link LanScan} engine. No permission beyond ACCESS_NETWORK_STATE is
 * used here; raw sockets are deliberately NOT attempted (they need root).
 *
 * The output is the JSON that both the diagnostics screen and the loopback
 * {@link LanBridge} hand to the user/agent.
 */
public final class LanDiscovery {

    private LanDiscovery() {}

    /** One non-loopback IPv4 interface the device currently owns. */
    public static final class Iface {
        public final String name;
        public final String address;
        public final int prefix;
        /** The link's real subnet, e.g. 192.168.1.0/24. */
        public final String cidr;
        /** The range actually scanned: a wide link is narrowed to our /24
         *  so a phone never blasts 65k addresses at a /16. */
        public final String scanCidr;

        Iface(String name, String address, int prefix, String cidr, String scanCidr) {
            this.name = name;
            this.address = address;
            this.prefix = prefix;
            this.cidr = cidr;
            this.scanCidr = scanCidr;
        }
    }

    /** Enumerate every usable IPv4 interface without touching the network. */
    public static List<Iface> interfaces(Context c) {
        Map<String, Iface> byIp = new LinkedHashMap<>();

        try {
            ConnectivityManager cm =
                    (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                for (Network n : cm.getAllNetworks()) {
                    LinkProperties lp = cm.getLinkProperties(n);
                    if (lp == null) continue;
                    String name = lp.getInterfaceName();
                    for (LinkAddress la : lp.getLinkAddresses()) {
                        add(byIp, name, la.getAddress(), la.getPrefixLength());
                    }
                }
            }
        } catch (Exception ignored) {
            // Fall through to NetworkInterface enumeration below.
        }

        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.isLoopback() || !ni.isUp()) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    add(byIp, ni.getName(), ia.getAddress(),
                            ia.getNetworkPrefixLength());
                }
            }
        } catch (Exception ignored) {
            // Keep whatever ConnectivityManager already produced.
        }

        return new ArrayList<>(byIp.values());
    }

    private static void add(Map<String, Iface> byIp, String name,
                            InetAddress address, int prefix) {
        if (!(address instanceof Inet4Address) || prefix < 0 || prefix > 32) return;
        String ip = address.getHostAddress();
        if (ip == null) return;
        if (ip.startsWith("127.") || ip.equals("0.0.0.0")) return;
        if (ip.startsWith("169.254.")) return;   // link-local: no useful hosts
        if (byIp.containsKey(ip)) return;
        String real = LanScan.normalizeCidr(ip + "/" + prefix);
        // A wide prefix (/16 and larger) is narrowed to our own /24 so the
        // scan stays bounded and actually covers the segment we are on.
        int scanPrefix = Math.max(prefix, 24);
        String scan = LanScan.normalizeCidr(ip + "/" + scanPrefix);
        byIp.put(ip, new Iface(name == null ? "?" : name, ip, prefix, real, scan));
    }

    /** Scan every interface with the default ports/timeout. */
    public static String scanJson(Context c) {
        return scanJson(c, LanScan.DEFAULT_PORTS, LanScan.DEFAULT_TIMEOUT_MS);
    }

    /** Full scan; returns the JSON document described in README/EnvNote. */
    public static String scanJson(Context c, int[] ports, int timeoutMs) {
        long t0 = System.currentTimeMillis();
        List<Iface> ifaces = interfaces(c);

        Set<String> subnets = new LinkedHashSet<>();
        for (Iface i : ifaces) subnets.add(i.scanCidr);

        List<Map<String, Object>> ifJson = new ArrayList<>();
        for (Iface i : ifaces) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", i.name);
            m.put("address", i.address);
            m.put("prefix", i.prefix);
            m.put("cidr", i.cidr);
            m.put("scanCidr", i.scanCidr);
            ifJson.add(m);
        }

        // Scan each distinct /24 once; a host seen on two interfaces keeps
        // the union of its open ports.
        Map<String, Map<String, Object>> byHost = new LinkedHashMap<>();
        int scanned = 0;
        for (String subnet : subnets) {
            LanScan.Result r = LanScan.scan(subnet, ports, timeoutMs,
                    LanScan.DEFAULT_THREADS, LanScan.socketProber());
            scanned += r.scanned;
            for (LanScan.Host h : r.hosts) {
                if (!h.alive) continue;
                Map<String, Object> prev = byHost.get(h.ip);
                if (prev == null) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("ip", h.ip);
                    m.put("via", h.via);
                    m.put("openPorts", new ArrayList<Object>(h.openPorts));
                    byHost.put(h.ip, m);
                } else {
                    @SuppressWarnings("unchecked")
                    List<Object> prevPorts = (List<Object>) prev.get("openPorts");
                    for (Integer p : h.openPorts) {
                        if (!prevPorts.contains(p)) prevPorts.add(p);
                    }
                    Collections.sort(prevPorts, (a, b) ->
                            Long.compare(((Number) a).longValue(),
                                    ((Number) b).longValue()));
                }
            }
        }

        List<Object> hosts = new ArrayList<Object>(byHost.values());
        Collections.sort(hosts, (a, b) -> Long.compare(
                LanScan.ipToLong(String.valueOf(((Map<?, ?>) a).get("ip"))),
                LanScan.ipToLong(String.valueOf(((Map<?, ?>) b).get("ip")))));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("generatedAt", System.currentTimeMillis());
        root.put("method", "tcp-connect");
        root.put("privileged", false);
        root.put("note", "Non-root TCP connect scan. Open ports are reliable; "
                + "a host that drops every probe cannot be seen. ARP/SYN "
                + "scanning and packet capture need root/adb (CAP_NET_RAW).");
        root.put("ports", toList(ports == null || ports.length == 0
                ? LanScan.DEFAULT_PORTS : ports));
        root.put("timeoutMs", timeoutMs > 0 ? timeoutMs : LanScan.DEFAULT_TIMEOUT_MS);
        root.put("interfaces", ifJson);
        root.put("subnets", new ArrayList<Object>(subnets));
        root.put("scanned", scanned);
        root.put("alive", hosts.size());
        root.put("hosts", hosts);
        root.put("durationMs", System.currentTimeMillis() - t0);
        return Json.write(root);
    }

    private static List<Object> toList(int[] values) {
        List<Object> out = new ArrayList<>(values.length);
        for (int v : values) out.add(v);
        return out;
    }

    /** Compact human summary for the diagnostics screen. */
    public static String summary(String json) {
        Object parsed = Json.parse(json);
        Map<String, Object> root = Json.obj(parsed);
        if (root == null) return "scan produced no parsable result";
        int alive = (int) Json.num(root, "alive");
        int scanned = (int) Json.num(root, "scanned");
        long ms = (long) Json.num(root, "durationMs");
        StringBuilder b = new StringBuilder();
        b.append("Scanned ").append(scanned).append(" host")
                .append(scanned == 1 ? "" : "s").append(" in ")
                .append(ms).append(" ms — ").append(alive)
                .append(alive == 1 ? " alive" : " alive");
        List<Object> hosts = Json.list(root, "hosts");
        if (hosts != null) {
            for (Object o : hosts) {
                Map<String, Object> h = Json.obj(o);
                if (h == null) continue;
                b.append("\n  ").append(Json.str(h, "ip"));
                List<Object> ports = Json.list(h, "openPorts");
                if (ports != null && !ports.isEmpty()) {
                    b.append("  open: ");
                    for (int i = 0; i < ports.size(); i++) {
                        if (i > 0) b.append(", ");
                        b.append(((Number) ports.get(i)).intValue());
                    }
                } else {
                    b.append("  up (no probed port open)");
                }
            }
        }
        return b.toString();
    }
}
