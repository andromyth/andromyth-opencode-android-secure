package ai.opencode.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.RouteInfo;
import android.net.wifi.WifiManager;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Android-side glue between the platform's interface/link data and the pure
 * {@link LanScan}/{@link LanProtocols} engines.
 *
 * <p>Beyond the original TCP-connect sweep this now runs the non-root
 * application-layer discovery that actually finds the silent devices a
 * connect scan misses:
 *
 * <ul>
 *   <li>mDNS / DNS-SD over {@code 224.0.0.251:5353} (service types, instance
 *       names, A records, TXT metadata)</li>
 *   <li>SSDP / UPnP M-SEARCH over {@code 239.255.255.250:1900}</li>
 *   <li>NetBIOS node-status queries (unicast {@code :137}) for Windows/Samba
 *       names</li>
 *   <li>reverse DNS (PTR) through the link's own resolver</li>
 * </ul>
 *
 * <p>mDNS/SSDP multicast requires holding a {@link WifiManager.MulticastLock}
 * (permission {@code CHANGE_WIFI_MULTICAST_STATE}); without it Android filters
 * multicast and the scan silently sees nothing. Everything remains
 * non-privileged: no raw sockets, no ARP, no packet capture. A best-effort
 * {@code /proc/net/arp} read adds MAC/vendor when the platform permits it.
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

    /** Which discovery engines to run, and how many TCP prober threads. */
    public static final class Options {
        public boolean mdns = true;
        public boolean ssdp = true;
        public boolean nbns = true;
        public boolean dns = true;
        public int threads = LanScan.DEFAULT_THREADS;
    }

    /** Active link facts used by the discovery engines. */
    private static final class NetInfo {
        final String gateway;
        final String localV4;
        final String ifaceName;
        final List<String> dns;
        final NetworkInterface iface;

        NetInfo(String gateway, String localV4, String ifaceName,
                List<String> dns, NetworkInterface iface) {
            this.gateway = gateway;
            this.localV4 = localV4;
            this.ifaceName = ifaceName;
            this.dns = dns;
            this.iface = iface;
        }
    }

    /** One observation from a discovery engine. */
    private static final class Found {
        final String ip;
        final String source;
        final String name;
        final String service;

        Found(String ip, String source, String name, String service) {
            this.ip = ip;
            this.source = source;
            this.name = name;
            this.service = service;
        }
    }

    /** Everything learned about one address, merged across engines. */
    private static final class HostAgg {
        final String ip;
        boolean alive;
        String via = "";
        final Set<Integer> ports = new TreeSet<>();
        final Set<String> sources = new LinkedHashSet<>();
        final Set<String> names = new LinkedHashSet<>();
        final Set<String> services = new LinkedHashSet<>();
        String hostname;
        String displayName;
        String mac;
        String vendor;
        String deviceType = "unknown";

        HostAgg(String ip) { this.ip = ip; }

        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", ip);
            if (hostname != null) m.put("hostname", hostname);
            if (displayName != null) m.put("name", displayName);
            m.put("deviceType", deviceType);
            m.put("via", via);
            m.put("openPorts", new ArrayList<Object>(ports));
            if (!services.isEmpty()) m.put("services", new ArrayList<Object>(services));
            if (mac != null) m.put("mac", mac);
            if (vendor != null) m.put("vendor", vendor);
            m.put("sources", new ArrayList<Object>(sources));
            return m;
        }
    }

    // ------------------------------------------------------------- interfaces

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

    // ----------------------------------------------------------------- scans

    /** Scan every interface with the default ports/timeout and full
     *  application-layer discovery. */
    public static String scanJson(Context c) {
        return scanJson(c, LanScan.DEFAULT_PORTS, LanScan.DEFAULT_TIMEOUT_MS, null);
    }

    /** Scan with custom ports/timeout and full discovery. */
    public static String scanJson(Context c, int[] ports, int timeoutMs) {
        return scanJson(c, ports, timeoutMs, null);
    }

    /** Run only the mDNS/DNS-SD engine and return a human-readable list.
     *  Uses the app's own multicast scanner instead of the platform
     *  NsdManager, which has crashed in its callback handler on some
     *  Android 14 builds. */
    public static String mdnsSummary(Context c) {
        WifiManager wm = null;
        try {
            wm = (WifiManager) c.getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
        } catch (Exception ignored) {
        }
        WifiManager.MulticastLock lock = null;
        if (wm != null) {
            try {
                lock = wm.createMulticastLock("oc-mdns-services");
                lock.setReferenceCounted(false);
                lock.acquire();
            } catch (Exception e) {
                lock = null;
            }
        }
        try {
            NetInfo net = netInfo(c);
            List<Found> found = mdnsDiscover(net);
            if (found.isEmpty())
                return "mDNS: no services found (no responders, or multicast is filtered by this network).";
            StringBuilder b = new StringBuilder("mDNS services:\n");
            for (Found f : found) {
                b.append("  ").append(f.ip);
                if (f.name != null && !f.name.isEmpty())
                    b.append(" · ").append(f.name);
                if (f.service != null && !f.service.isEmpty())
                    b.append(" · ").append(f.service);
                b.append('\n');
            }
            return b.toString();
        } finally {
            if (lock != null) {
                try { lock.release(); } catch (Exception ignored) {}
            }
        }
    }

    /** Full scan; returns the JSON document described in README/EnvNote. */
    public static String scanJson(Context c, int[] ports, int timeoutMs, Options opt) {
        if (opt == null) opt = new Options();
        final int[] usePorts = (ports == null || ports.length == 0)
                ? LanScan.DEFAULT_PORTS : ports;
        final int useTimeout = timeoutMs > 0 ? timeoutMs : LanScan.DEFAULT_TIMEOUT_MS;
        final int useThreads = opt.threads > 0 ? opt.threads : LanScan.DEFAULT_THREADS;
        final boolean wantMdns = opt.mdns;
        final boolean wantSsdp = opt.ssdp;
        final boolean wantNbns = opt.nbns;
        final boolean wantDns = opt.dns;

        long t0 = System.currentTimeMillis();
        List<Iface> ifaces = interfaces(c);
        final NetInfo net = netInfo(c);

        Set<String> subnets = new LinkedHashSet<>();
        for (Iface i : ifaces) subnets.add(i.scanCidr);

        final List<String> candidates = new ArrayList<>();
        for (String s : subnets) candidates.addAll(LanScan.candidateHosts(s));

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

        WifiManager wm = null;
        try {
            wm = (WifiManager) c.getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
        } catch (Exception ignored) {
        }
        WifiManager.MulticastLock lock = null;
        if ((wantMdns || wantSsdp) && wm != null) {
            try {
                lock = wm.createMulticastLock("oc-lan-discovery");
                lock.setReferenceCounted(false);
                lock.acquire();
            } catch (Exception e) {
                lock = null;   // no multicast permission: unicast still works
            }
        }

        ExecutorService pool = Executors.newFixedThreadPool(4);
        Map<String, HostAgg> agg = new LinkedHashMap<>();
        int scanned = 0;
        try {
            Future<List<Found>> mdnsF = wantMdns
                    ? pool.submit(() -> mdnsDiscover(net)) : null;
            Future<List<Found>> ssdpF = wantSsdp
                    ? pool.submit(() -> ssdpDiscover(net)) : null;
            Future<List<Found>> nbnsF = wantNbns
                    ? pool.submit(() -> nbnsSweep(candidates)) : null;

            // TCP connect sweep runs on this thread while discovery runs in
            // the pool, so the two do not serialise.
            for (String subnet : subnets) {
                LanScan.Result r = LanScan.scan(subnet, usePorts, useTimeout,
                        useThreads, LanScan.socketProber());
                scanned += r.scanned;
                for (LanScan.Host h : r.hosts) {
                    if (!h.alive) continue;
                    HostAgg a = agg.get(h.ip);
                    if (a == null) { a = new HostAgg(h.ip); agg.put(h.ip, a); }
                    a.alive = true;
                    if (a.via.isEmpty()) a.via = h.via;
                    a.ports.addAll(h.openPorts);
                    a.sources.add("tcp");
                }
            }

            merge(agg, futureGet(mdnsF, 2600));
            merge(agg, futureGet(ssdpF, 2600));
            merge(agg, futureGet(nbnsF, 2100));

            if (wantDns && net != null && !net.dns.isEmpty()) {
                List<Future<?>> futs = new ArrayList<>();
                int budget = 64;
                for (final HostAgg a : agg.values()) {
                    if (budget-- <= 0) break;
                    if (a.hostname != null) continue;
                    futs.add(pool.submit(() -> {
                        String h = reverseDns(a.ip, net.dns);
                        if (h != null && !h.isEmpty()) a.hostname = h;
                    }));
                }
                for (Future<?> f : futs) {
                    try { f.get(1500, TimeUnit.MILLISECONDS); }
                    catch (Exception ignored) { /* leave hostname unset */ }
                }
            }

            Map<String, String> arp = arpTable();
            for (HostAgg a : agg.values()) finalizeHost(a, net, arp);

            List<Object> hosts = new ArrayList<>(agg.size());
            for (HostAgg a : agg.values()) hosts.add(a.toJson());
            Collections.sort(hosts, (a, b) -> Long.compare(
                    LanScan.ipToLong(String.valueOf(((Map<?, ?>) a).get("ip"))),
                    LanScan.ipToLong(String.valueOf(((Map<?, ?>) b).get("ip")))));

            Map<String, Object> discovery = new LinkedHashMap<>();
            discovery.put("mdns", wantMdns);
            discovery.put("ssdp", wantSsdp);
            discovery.put("nbns", wantNbns);
            discovery.put("dns", wantDns);

            Map<String, Object> root = new LinkedHashMap<>();
            root.put("generatedAt", System.currentTimeMillis());
            root.put("method", "tcp-connect+mdns+ssdp+nbns");
            root.put("privileged", false);
            root.put("note", "Non-root discovery: TCP connect plus mDNS/SSDP/"
                    + "NetBIOS/reverse-DNS. Hosts that answer no probe at all "
                    + "still need ARP/root or the router's DHCP lease table.");
            root.put("ports", toList(usePorts));
            root.put("timeoutMs", useTimeout);
            root.put("threads", useThreads);
            root.put("interfaces", ifJson);
            root.put("subnets", new ArrayList<Object>(subnets));
            root.put("gateway", net == null ? null : net.gateway);
            root.put("dns", net == null ? new ArrayList<Object>() : new ArrayList<Object>(net.dns));
            root.put("ipv6", new ArrayList<Object>(ipv6Addresses()));
            root.put("discovery", discovery);
            root.put("scanned", scanned);
            root.put("alive", hosts.size());
            root.put("hosts", hosts);
            root.put("durationMs", System.currentTimeMillis() - t0);
            return Json.write(root);
        } finally {
            pool.shutdownNow();
            if (lock != null) {
                try { lock.release(); } catch (Exception ignored) {}
            }
        }
    }

    private static List<Found> futureGet(Future<List<Found>> f, long ms) {
        if (f == null) return Collections.emptyList();
        try {
            List<Found> r = f.get(ms, TimeUnit.MILLISECONDS);
            return r == null ? Collections.<Found>emptyList() : r;
        } catch (Exception e) {
            f.cancel(true);
            return Collections.emptyList();
        }
    }

    private static void merge(Map<String, HostAgg> agg, List<Found> found) {
        for (Found f : found) {
            if (f == null || f.ip == null || f.ip.isEmpty()) continue;
            HostAgg a = agg.get(f.ip);
            if (a == null) { a = new HostAgg(f.ip); agg.put(f.ip, a); }
            if (a.via.isEmpty() && !a.alive) a.via = f.source;
            a.sources.add(f.source);
            if (f.service != null && !f.service.isEmpty())
                a.services.add(LanProtocols.trimDot(f.service));
            if (f.name != null && !f.name.isEmpty())
                a.names.add(LanProtocols.trimDot(f.name));
        }
    }

    // ------------------------------------------------------------ mDNS / SSDP

    private static MulticastSocket openMdnsSocket() {
        try {
            MulticastSocket s = new MulticastSocket(null);
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(LanProtocols.MDNS_PORT));
            return s;
        } catch (Exception e) {
            try {
                return new MulticastSocket(0);   // fall back to QU-only replies
            } catch (Exception e2) {
                return null;
            }
        }
    }

    private static List<Found> mdnsDiscover(NetInfo net) {
        List<Found> out = new ArrayList<>();
        MulticastSocket s = null;
        InetAddress group = null;
        try {
            group = InetAddress.getByName(LanProtocols.MDNS_GROUP);
            s = openMdnsSocket();
            if (s == null) return out;
            try { s.setTimeToLive(1); } catch (Exception ignored) {}
            if (net != null && net.iface != null) {
                try { s.setNetworkInterface(net.iface); } catch (Exception ignored) {}
                try {
                    s.joinGroup(new InetSocketAddress(group, LanProtocols.MDNS_PORT),
                            net.iface);
                } catch (Exception ignored) {}
            } else {
                try { s.joinGroup(group); } catch (Exception ignored) {}
            }
            s.setSoTimeout(250);

            for (String svc : LanProtocols.MDNS_SERVICES) {
                byte[] q = LanProtocols.mdnsQuery(svc);
                try {
                    s.send(new DatagramPacket(q, q.length, group,
                            LanProtocols.MDNS_PORT));
                } catch (Exception ignored) {}
            }

            long deadline = System.currentTimeMillis() + 1800;
            byte[] buf = new byte[8192];
            Set<String> seen = new HashSet<>();
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                } catch (SocketTimeoutException te) {
                    continue;
                } catch (Exception e) {
                    break;
                }
                String ip = p.getAddress().getHostAddress();
                byte[] data = Arrays.copyOf(p.getData(), p.getLength());
                LanProtocols.Dns d = LanProtocols.parseDns(data);
                if (d == null) continue;

                List<String> serviceTypes = new ArrayList<>();
                List<String> instanceNames = new ArrayList<>();
                for (String n : d.ptr) {
                    if (LanProtocols.isServiceType(n)) serviceTypes.add(n);
                    else {
                        String label = LanProtocols.instanceLabel(n);
                        if (!label.isEmpty()) instanceNames.add(label);
                    }
                }
                String display = null;
                for (String t : d.txt) {
                    if (t.startsWith("fn=")) { display = t.substring(3); break; }
                }
                if (display == null && !instanceNames.isEmpty())
                    display = instanceNames.get(0);
                String srvHost = null;
                for (String sv : d.srv) {
                    int c = sv.lastIndexOf(':');
                    if (c > 0) {
                        String target = sv.substring(0, c);
                        if (target.indexOf('.') > 0) { srvHost = target; break; }
                    }
                }

                Set<String> ips = new LinkedHashSet<>();
                if (!d.ipv4.isEmpty()) ips.addAll(d.ipv4);
                ips.add(ip);
                for (String hostIp : ips) {
                    String firstSvc = serviceTypes.isEmpty()
                            ? null : serviceTypes.get(0);
                    String key = hostIp + "|" + firstSvc + "|" + display;
                    if (seen.add(key))
                        out.add(new Found(hostIp, "mdns", display, firstSvc));
                    for (int i = 1; i < serviceTypes.size(); i++) {
                        String svc = serviceTypes.get(i);
                        if (seen.add(hostIp + "|" + svc))
                            out.add(new Found(hostIp, "mdns", null, svc));
                    }
                    if (srvHost != null && seen.add(hostIp + "|h|" + srvHost))
                        out.add(new Found(hostIp, "mdns", srvHost, null));
                }
            }

            if (net != null && net.iface != null) {
                try {
                    s.leaveGroup(new InetSocketAddress(group,
                            LanProtocols.MDNS_PORT), net.iface);
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {
        } finally {
            if (s != null) try { s.close(); } catch (Exception ignored) {}
        }
        return out;
    }

    private static List<Found> ssdpDiscover(NetInfo net) {
        List<Found> out = new ArrayList<>();
        MulticastSocket s = null;
        try {
            s = new MulticastSocket(0);
            if (net != null && net.iface != null) {
                try { s.setNetworkInterface(net.iface); } catch (Exception ignored) {}
                try { s.setTimeToLive(1); } catch (Exception ignored) {}
            }
            s.setSoTimeout(250);
            byte[] q = LanProtocols.ssdpSearch();
            InetAddress group = InetAddress.getByName(LanProtocols.SSDP_GROUP);
            s.send(new DatagramPacket(q, q.length, group,
                    LanProtocols.SSDP_PORT));

            long deadline = System.currentTimeMillis() + 2000;
            byte[] buf = new byte[4096];
            Set<String> seen = new HashSet<>();
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                } catch (SocketTimeoutException te) {
                    continue;
                } catch (Exception e) {
                    break;
                }
                String ip = p.getAddress().getHostAddress();
                byte[] data = Arrays.copyOf(p.getData(), p.getLength());
                Map<String, String> h = LanProtocols.parseSsdp(data);
                String st = h.get("st");
                String usn = h.get("usn");
                String server = h.get("server");
                String name = usn != null ? usn : server;
                if (seen.add(ip + "|" + st))
                    out.add(new Found(ip, "ssdp", null, st != null ? st : name));
            }
        } catch (Exception ignored) {
        } finally {
            if (s != null) try { s.close(); } catch (Exception ignored) {}
        }
        return out;
    }

    // ------------------------------------------------------------------ NBNS

    private static List<Found> nbnsSweep(List<String> candidates) {
        List<Found> out = new ArrayList<>();
        DatagramSocket s = null;
        try {
            s = new DatagramSocket();
            s.setSoTimeout(200);
            byte[] q = LanProtocols.nbnsStatusQuery();
            for (String ip : candidates) {
                try {
                    s.send(new DatagramPacket(q, q.length,
                            InetAddress.getByName(ip), LanProtocols.NBNS_PORT));
                } catch (Exception ignored) {}
            }
            long deadline = System.currentTimeMillis() + 1500;
            byte[] buf = new byte[2048];
            Set<String> seen = new HashSet<>();
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                } catch (SocketTimeoutException te) {
                    continue;
                } catch (Exception e) {
                    break;
                }
                String ip = p.getAddress().getHostAddress();
                byte[] data = Arrays.copyOf(p.getData(), p.getLength());
                for (String name : LanProtocols.parseNbns(data)) {
                    if (seen.add(ip + "|" + name))
                        out.add(new Found(ip, "nbns", name, null));
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (s != null) try { s.close(); } catch (Exception ignored) {}
        }
        return out;
    }

    // ------------------------------------------------------------ reverse DNS

    private static String reverseDns(String ip, List<String> servers) {
        for (String server : servers) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                s.setSoTimeout(400);
                byte[] q = LanProtocols.ptrQuery(ip);
                InetAddress a = InetAddress.getByName(server);
                s.send(new DatagramPacket(q, q.length, a, LanProtocols.DNS_PORT));
                byte[] buf = new byte[2048];
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                s.receive(p);
                byte[] data = Arrays.copyOf(p.getData(), p.getLength());
                LanProtocols.Dns d = LanProtocols.parseDns(data);
                if (d != null) {
                    for (String n : d.ptr) {
                        String t = LanProtocols.trimDot(n);
                        if (!t.isEmpty()
                                && !t.equalsIgnoreCase("localhost")) return t;
                    }
                }
            } catch (Exception ignored) {
                // try the next resolver
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
        return null;
    }

    // ------------------------------------------------------------- enrichment

    private static Map<String, String> arpTable() {
        Map<String, String> out = new HashMap<>();
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            boolean header = true;
            while ((line = r.readLine()) != null) {
                if (header) { header = false; continue; }
                String[] p = line.trim().split("\\s+");
                if (p.length < 4) continue;
                String mac = p[3];
                if (mac == null || mac.equals("00:00:00:00:00:00")) continue;
                if (!mac.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) continue;
                out.put(p[0], mac.toLowerCase(Locale.US));
            }
        } catch (Exception ignored) {
            // Non-root Android usually denies /proc/net/arp; MAC stays absent.
        } finally {
            if (r != null) try { r.close(); } catch (Exception ignored) {}
        }
        return out;
    }

    private static List<String> ipv6Addresses() {
        Set<String> out = new LinkedHashSet<>();
        try {
            for (NetworkInterface ni : Collections.list(
                    NetworkInterface.getNetworkInterfaces())) {
                if (ni.isLoopback() || !ni.isUp()) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress a = ia.getAddress();
                    if (!(a instanceof Inet6Address)) continue;
                    String h = a.getHostAddress();
                    int pct = h.indexOf('%');
                    if (pct > 0) h = h.substring(0, pct);
                    if (h.isEmpty() || h.equals("::1")) continue;
                    out.add(h + "/" + ia.getNetworkPrefixLength());
                }
            }
        } catch (Exception ignored) {
        }
        return new ArrayList<>(out);
    }

    private static void finalizeHost(HostAgg a, NetInfo net, Map<String, String> arp) {
        a.mac = arp.get(a.ip);
        if (a.mac != null) a.vendor = OuiVendor.vendor(a.mac);
        if (a.hostname == null) {
            for (String n : a.names) {
                String t = LanProtocols.trimDot(n);
                if (t.indexOf('.') > 0 && !t.startsWith("_")) {
                    a.hostname = t;
                    break;
                }
            }
        }
        if (a.displayName == null) {
            for (String n : a.names) {
                String t = LanProtocols.trimDot(n);
                if (t.indexOf('.') <= 0 && !t.isEmpty() && !t.startsWith("_")) {
                    a.displayName = t;
                    break;
                }
            }
        }
        if (a.displayName == null) {
            for (String n : a.names) {
                String t = LanProtocols.instanceLabel(n);
                if (!t.isEmpty()) { a.displayName = t; break; }
            }
        }
        if (a.via.isEmpty()) {
            a.via = a.sources.isEmpty() ? "" : a.sources.iterator().next();
        }
        a.deviceType = classify(a, net);
    }

    private static String classify(HostAgg a, NetInfo net) {
        if (net != null && net.gateway != null && net.gateway.equals(a.ip))
            return "router";
        String svc = joinLower(a.services);
        String hn = ((a.hostname == null ? "" : a.hostname) + " "
                + (a.displayName == null ? "" : a.displayName))
                .toLowerCase(Locale.US);
        if (a.ports.contains(631) || a.ports.contains(515)
                || a.ports.contains(9100) || svc.contains("_ipp")
                || svc.contains("_printer") || svc.contains("printer"))
            return "printer";
        if (svc.contains("_googlecast") || svc.contains("_airplay")
                || svc.contains("_raop") || svc.contains("mediarenderer")
                || a.ports.contains(554) || a.ports.contains(32400)
                || a.ports.contains(9000))
            return "media";
        if (a.ports.contains(3389) || a.ports.contains(445)
                || a.ports.contains(139) || a.ports.contains(22))
            return "computer";
        if (hn.contains("android") || hn.contains("phone") || hn.contains("iphone")
                || hn.contains("ipad") || hn.contains("samsung")
                || hn.contains("galaxy") || hn.contains("pixel")
                || hn.contains("redmi") || hn.contains("oneplus"))
            return "phone";
        if (a.ports.contains(1883) || a.ports.contains(8883)
                || svc.contains("_hap") || svc.contains("_matter"))
            return "iot";
        if (svc.contains("internetgateway") || svc.contains("_router")
                || a.ports.contains(53))
            return "router";
        return "unknown";
    }

    private static String joinLower(Set<String> values) {
        StringBuilder b = new StringBuilder();
        for (String v : values) {
            if (b.length() > 0) b.append(' ');
            b.append(v.toLowerCase(Locale.US));
        }
        return b.toString();
    }

    // -------------------------------------------------------------- link info

    private static NetInfo netInfo(Context c) {
        String gateway = null;
        String local = null;
        String ifaceName = null;
        List<String> dns = new ArrayList<>();
        NetworkInterface ni = null;
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    c.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network best = null;
                LinkProperties bestLp = null;
                for (Network n : cm.getAllNetworks()) {
                    LinkProperties lp = cm.getLinkProperties(n);
                    if (lp == null) continue;
                    String nm = lp.getInterfaceName();
                    if (nm == null) continue;
                    if (bestLp == null) { best = n; bestLp = lp; }
                    if (nm.startsWith("wlan") || nm.startsWith("ap")) {
                        best = n;
                        bestLp = lp;
                        if (nm.startsWith("wlan")) break;
                    }
                }
                if (bestLp != null) {
                    ifaceName = bestLp.getInterfaceName();
                    for (InetAddress d : bestLp.getDnsServers()) {
                        if (d != null) dns.add(d.getHostAddress());
                    }
                    for (LinkAddress la : bestLp.getLinkAddresses()) {
                        InetAddress a = la.getAddress();
                        if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                            local = a.getHostAddress();
                            break;
                        }
                    }
                    for (RouteInfo r : bestLp.getRoutes()) {
                        InetAddress gw = r.getGateway();
                        if (r.isDefaultRoute() && gw instanceof Inet4Address) {
                            gateway = gw.getHostAddress();
                            break;
                        }
                    }
                    if (gateway == null && local != null) {
                        int dot = local.lastIndexOf('.');
                        if (dot > 0) gateway = local.substring(0, dot) + ".1";
                    }
                    if (ifaceName != null) {
                        try { ni = NetworkInterface.getByName(ifaceName); }
                        catch (Exception ignored) {}
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return new NetInfo(gateway, local, ifaceName, dns, ni);
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
                .append(" device").append(alive == 1 ? "" : "s");
        String gateway = Json.str(root, "gateway");
        if (gateway != null) b.append(" · gateway ").append(gateway);
        List<Object> hosts = Json.list(root, "hosts");
        if (hosts != null) {
            for (Object o : hosts) {
                Map<String, Object> h = Json.obj(o);
                if (h == null) continue;
                b.append("\n  ").append(Json.str(h, "ip"));
                String hostname = Json.str(h, "hostname");
                String name = Json.str(h, "name");
                if (hostname != null) b.append("  ").append(hostname);
                else if (name != null) b.append("  \"").append(name).append('"');
                String type = Json.str(h, "deviceType");
                if (type != null && !"unknown".equals(type))
                    b.append("  [").append(type).append(']');
                String vendor = Json.str(h, "vendor");
                if (vendor != null) b.append("  ").append(vendor);
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
                List<Object> services = Json.list(h, "services");
                if (services != null && !services.isEmpty()) {
                    b.append("  services: ");
                    for (int i = 0; i < services.size(); i++) {
                        if (i > 0) b.append(", ");
                        b.append(String.valueOf(services.get(i)));
                    }
                }
            }
        }
        return b.toString();
    }
}
