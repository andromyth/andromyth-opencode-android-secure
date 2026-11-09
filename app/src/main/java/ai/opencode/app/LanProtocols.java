package ai.opencode.app;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wire formats for the LAN discovery probes the bridge can run without root:
 * mDNS/DNS-SD (multicast), SSDP/UPnP (multicast), NetBIOS-NS node status
 * (unicast) and plain DNS PTR lookups (unicast).
 *
 * <p>Pure Java on purpose — no Android imports — so every encoder and parser
 * is unit-testable on the JVM without a socket or a live LAN. The socket
 * orchestration lives in {@link LanDiscovery}.
 */
public final class LanProtocols {

    private LanProtocols() {}

    public static final String MDNS_GROUP = "224.0.0.251";
    public static final int MDNS_PORT = 5353;
    public static final String SSDP_GROUP = "239.255.255.250";
    public static final int SSDP_PORT = 1900;
    public static final int NBNS_PORT = 137;
    public static final int DNS_PORT = 53;

    /** Service types queried for mDNS. Each is one small PTR query; the set
     *  is deliberately curated so a scan does not flood the segment. */
    public static final String[] MDNS_SERVICES = {
            "_services._dns-sd._udp.local",
            "_http._tcp.local",
            "_https._tcp.local",
            "_ipp._tcp.local",
            "_printer._tcp.local",
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_googlecast._tcp.local",
            "_spotify-connect._tcp.local",
            "_workstation._tcp.local",
            "_smb._tcp.local",
            "_device-info._tcp.local",
            "_ssh._tcp.local",
            "_adb-tls-connect._tcp.local"
    };

    // ------------------------------------------------------------- encoders

    /** mDNS PTR query with the unicast-response (QU) bit set, so responders
     *  reply directly to our ephemeral port even when :5353 cannot be bound. */
    public static byte[] mdnsQuery(String service) {
        return dnsQuery(0, service, 12, 0x8001);
    }

    /** DNS PTR lookup for an IPv4 literal (reverse in-addr.arpa). */
    public static byte[] ptrQuery(String ip) {
        String name;
        if (ip != null) {
            String[] p = ip.trim().split("\\.");
            if (p.length == 4) {
                name = p[3] + "." + p[2] + "." + p[1] + "." + p[0]
                        + ".in-addr.arpa";
            } else {
                name = ip.trim();
            }
        } else {
            name = "0.0.0.0.in-addr.arpa";
        }
        return dnsQuery(0x0100, name, 12, 1);
    }

    /** SSDP discovery datagram (M-SEARCH, MX:1 keeps the wait short). */
    public static byte[] ssdpSearch() {
        String s = "M-SEARCH * HTTP/1.1\r\n"
                + "HOST: 239.255.255.250:1900\r\n"
                + "MAN: \"ssdp:discover\"\r\n"
                + "MX: 1\r\n"
                + "ST: ssdp:all\r\n"
                + "USER-AGENT: OpenCode-LAN/1.0 UPnP/1.1\r\n\r\n";
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** NetBIOS node-status query for the wildcard name "*", first-level
     *  encoded as the protocol requires. */
    public static byte[] nbnsStatusQuery() {
        ByteArrayOutputStream o = new ByteArrayOutputStream(64);
        writeU16(o, 0x1234);           // transaction id
        writeU16(o, 0x0000);           // flags: query
        writeU16(o, 0x0001);           // qdcount
        writeU16(o, 0x0000);           // ancount
        writeU16(o, 0x0000);           // nscount
        writeU16(o, 0x0000);           // arcount
        o.write(0x20);                 // 32-char encoded NetBIOS name
        byte[] raw = new byte[16];
        raw[0] = '*';
        for (int i = 0; i < 16; i++) {
            int c = raw[i] & 0xFF;
            o.write('A' + (c >> 4));
            o.write('A' + (c & 0x0F));
        }
        o.write(0x00);                 // name terminator
        writeU16(o, 0x0021);           // NBSTAT
        writeU16(o, 0x0001);           // IN
        return o.toByteArray();
    }

    private static byte[] dnsQuery(int flags, String name, int type, int qclass) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(96);
        writeU16(o, 0x0000);           // id (mDNS requires 0)
        writeU16(o, flags);
        writeU16(o, 1);                // qdcount
        writeU16(o, 0);
        writeU16(o, 0);
        writeU16(o, 0);
        writeName(o, name);
        writeU16(o, type);
        writeU16(o, qclass);
        return o.toByteArray();
    }

    private static void writeName(ByteArrayOutputStream o, String name) {
        if (name == null) { o.write(0); return; }
        String[] labels = name.split("\\.");
        for (String label : labels) {
            if (label.isEmpty()) continue;
            byte[] b = label.getBytes(StandardCharsets.ISO_8859_1);
            if (b.length > 63) b = java.util.Arrays.copyOf(b, 63);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
    }

    private static void writeU16(ByteArrayOutputStream o, int v) {
        o.write((v >>> 8) & 0xFF);
        o.write(v & 0xFF);
    }

    // -------------------------------------------------------------- parsers

    /** Decoded subset of a DNS/mDNS response: the records that help identify
     *  a device. All lists are non-null. */
    public static final class Dns {
        public final List<String> questions = new ArrayList<>();
        public final List<String> ptr = new ArrayList<>();
        public final List<String> srv = new ArrayList<>();
        public final List<String> txt = new ArrayList<>();
        public final List<String> ipv4 = new ArrayList<>();
        public final List<String> ipv6 = new ArrayList<>();
    }

    /** Parse a DNS/mDNS/PTR response. Returns null when the packet is not a
     *  DNS message; malformed tails are ignored rather than thrown. */
    public static Dns parseDns(byte[] d) {
        if (d == null || d.length < 12) return null;
        int qd = u16(d, 4);
        int an = u16(d, 6);
        int ns = u16(d, 8);
        int ar = u16(d, 10);
        Dns out = new Dns();
        int off = 12;
        for (int i = 0; i < qd && off < d.length; i++) {
            int[] o = {off};
            String q = readName(d, o);
            off = o[0];
            if (off + 4 > d.length) return out;
            out.questions.add(q);
            off += 4;
        }
        int total = an + ns + ar;
        for (int i = 0; i < total && off + 10 <= d.length; i++) {
            int[] o = {off};
            readName(d, o);            // owner name (unused)
            off = o[0];
            if (off + 10 > d.length) break;
            int type = u16(d, off);
            int rdlen = u16(d, off + 8);
            off += 10;
            int rstart = off;
            if (rdlen < 0 || rstart + rdlen > d.length) break;
            switch (type) {
                case 1:                                  // A
                    if (rdlen == 4) out.ipv4.add(ipv4(d, rstart));
                    break;
                case 28:                                 // AAAA
                    if (rdlen == 16) out.ipv6.add(ipv6(d, rstart));
                    break;
                case 12: {                               // PTR
                    int[] ro = {rstart};
                    String p = readName(d, ro);
                    if (!p.isEmpty()) out.ptr.add(p);
                    break;
                }
                case 33:                                 // SRV
                    if (rdlen >= 7) {
                        int port = u16(d, rstart + 4);
                        int[] ro = {rstart + 6};
                        String target = readName(d, ro);
                        out.srv.add(target + ":" + port);
                    }
                    break;
                case 16: {                               // TXT
                    int p = rstart;
                    int end = rstart + rdlen;
                    while (p < end) {
                        int len = d[p] & 0xFF;
                        p++;
                        if (len == 0 || p + len > end) break;
                        out.txt.add(new String(d, p, len,
                                StandardCharsets.UTF_8));
                        p += len;
                    }
                    break;
                }
                default:
                    break;
            }
            off = rstart + rdlen;
        }
        return out;
    }

    /** Parse an SSDP response into lowercase header name → value. */
    public static Map<String, String> parseSsdp(byte[] d) {
        Map<String, String> out = new LinkedHashMap<>();
        if (d == null) return out;
        String text = new String(d, StandardCharsets.ISO_8859_1);
        String[] lines = text.split("\r\n|\\n");
        if (lines.length > 0) out.put("_status", lines[0].trim());
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String key = line.substring(0, colon).trim().toLowerCase(
                    java.util.Locale.US);
            String val = line.substring(colon + 1).trim();
            if (!key.isEmpty()) out.put(key, val);
        }
        return out;
    }

    /** Parse the NetBIOS names out of an NBSTAT response. */
    public static List<String> parseNbns(byte[] d) {
        List<String> out = new ArrayList<>();
        if (d == null || d.length < 12) return out;
        int qd = u16(d, 4);
        int an = u16(d, 6);
        int ns = u16(d, 8);
        int ar = u16(d, 10);
        int off = 12;
        for (int i = 0; i < qd && off < d.length; i++) {
            int[] o = {off};
            readName(d, o);
            off = o[0];
            if (off + 4 > d.length) return out;
            off += 4;
        }
        int total = an + ns + ar;
        for (int i = 0; i < total && off + 10 <= d.length; i++) {
            int[] o = {off};
            readName(d, o);
            off = o[0];
            if (off + 10 > d.length) break;
            int type = u16(d, off);
            int rdlen = u16(d, off + 8);
            off += 10;
            int rstart = off;
            if (rstart + rdlen > d.length) break;
            if (type == 0x21 && rdlen >= 1) {
                int count = d[rstart] & 0xFF;
                int p = rstart + 1;
                for (int j = 0; j < count && p + 18 <= rstart + rdlen; j++) {
                    String name = new String(d, p, 15,
                            StandardCharsets.ISO_8859_1).trim();
                    if (!name.isEmpty()) out.add(name);
                    p += 18;
                }
            }
            off = rstart + rdlen;
        }
        return out;
    }

    /** True when a DNS-SD name names a service type (starts with "_"), as
     *  opposed to an instance like "Living Room TV._airplay._tcp.local". */
    public static boolean isServiceType(String name) {
        return name != null && name.trim().startsWith("_");
    }

    /** Strip the service suffix from an mDNS instance name so it can be
     *  shown as a human label ("Living Room TV._airplay._tcp.local" →
     *  "Living Room TV"). */
    public static String instanceLabel(String name) {
        if (name == null) return "";
        String s = name.trim();
        int dot = s.indexOf("._");
        if (dot > 0) s = s.substring(0, dot);
        return trimDot(s);
    }

    /** Remove a single trailing dot from an FQDN. */
    public static String trimDot(String s) {
        if (s == null) return "";
        String t = s.trim();
        while (t.endsWith(".")) t = t.substring(0, t.length() - 1);
        return t;
    }

    // ---------------------------------------------------------- DNS internals

    private static int u16(byte[] d, int off) {
        if (off < 0 || off + 1 >= d.length) return 0;
        return ((d[off] & 0xFF) << 8) | (d[off + 1] & 0xFF);
    }

    private static String ipv4(byte[] d, int off) {
        return (d[off] & 0xFF) + "." + (d[off + 1] & 0xFF) + "."
                + (d[off + 2] & 0xFF) + "." + (d[off + 3] & 0xFF);
    }

    private static String ipv6(byte[] d, int off) {
        StringBuilder b = new StringBuilder(39);
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) b.append(':');
            b.append(Integer.toHexString(
                    ((d[off + i] & 0xFF) << 8) | (d[off + i + 1] & 0xFF)));
        }
        return b.toString();
    }

    /** DNS name reader that honours compression pointers. {@code off[0]} is
     *  updated to the byte just past the name in the ORIGINAL stream. */
    private static String readName(byte[] d, int[] off) {
        StringBuilder b = new StringBuilder();
        int pos = off[0];
        boolean jumped = false;
        int guard = 0;
        while (guard++ < 128) {
            if (pos < 0 || pos >= d.length) break;
            int len = d[pos] & 0xFF;
            if (len == 0) {
                pos++;
                if (!jumped) off[0] = pos;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                if (pos + 1 >= d.length) break;
                int ptr = ((len & 0x3F) << 8) | (d[pos + 1] & 0xFF);
                if (!jumped) {
                    off[0] = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                continue;
            }
            if (pos + 1 + len > d.length) break;
            String label = new String(d, pos + 1, len,
                    StandardCharsets.ISO_8859_1);
            if (b.length() > 0) b.append('.');
            b.append(label);
            pos += 1 + len;
            if (!jumped) off[0] = pos;
        }
        return b.toString();
    }
}
