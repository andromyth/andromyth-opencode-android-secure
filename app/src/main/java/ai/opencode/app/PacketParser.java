package ai.opencode.app;

import java.util.Locale;

/**
 * Wireshark-style dissection of a captured frame.
 *
 * <p>Two link-layer shapes are accepted:
 * <ul>
 *   <li><b>Raw IP</b> — what a {@code VpnService} tun descriptor delivers:
 *       the buffer starts with the IPv4/IPv6 header. This is the case the
 *       original parser missed, which silently dropped every captured
 *       packet.</li>
 *   <li><b>Ethernet</b> — what a pcap/af_packet source delivers: 14-byte
 *       header followed by IPv4 (0x0800) or IPv6 (0x86DD).</li>
 * </ul>
 *
 * <p>Both IPv4 and IPv6 are dissected, TCP flags are decoded, and a
 * best-effort application protocol (HTTP/TLS/DNS/…) is inferred from ports
 * and the first payload bytes so the capture list reads like Wireshark's
 * "Protocol" column. Nothing here touches the network or Android APIs.
 */
public final class PacketParser {

    private PacketParser() {}

    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;
    public static final int PROTO_ICMPV6 = 58;

    private static final int ETH_IPV4 = 0x0800;
    private static final int ETH_IPV6 = 0x86DD;
    private static final int ETH_HEADER = 14;

    /** Parse one captured frame. Returns null when it is not a parseable
     *  IP packet (a control frame, a non-IP Ethernet type, or truncated). */
    public static Packet parse(long timeMs, byte[] frame) {
        if (frame == null || frame.length < 1) return null;
        int ipStart;
        int version;
        int first = frame[0] & 0xF0;
        if (first == 0x40) {
            ipStart = 0;
            version = 4;
        } else if (first == 0x60) {
            ipStart = 0;
            version = 6;
        } else if (frame.length >= ETH_HEADER) {
            int ethType = u16(frame, 12);
            if (ethType == ETH_IPV4) {
                ipStart = ETH_HEADER;
                version = 4;
            } else if (ethType == ETH_IPV6) {
                ipStart = ETH_HEADER;
                version = 6;
            } else {
                return null;
            }
        } else {
            return null;
        }
        return version == 4 ? parseV4(timeMs, frame, ipStart)
                : parseV6(timeMs, frame, ipStart);
    }

    // ---------------------------------------------------------------- IPv4

    private static Packet parseV4(long timeMs, byte[] f, int ipStart) {
        if (f.length < ipStart + 20) return null;
        int versionIhl = u8(f, ipStart);
        if ((versionIhl >>> 4) != 4) return null;
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || ipStart + ihl > f.length) return null;

        int totalLen = u16(f, ipStart + 2);
        if (totalLen < ihl) totalLen = f.length - ipStart;
        int proto = u8(f, ipStart + 9);
        int fragField = u16(f, ipStart + 6);
        boolean firstFragment = (fragField & 0x1FFF) == 0;
        int captured = f.length - ipStart;

        String src = ipv4(f, ipStart + 12);
        String dst = ipv4(f, ipStart + 16);
        int l4 = ipStart + ihl;
        int l4Len = totalLen - ihl;
        if (l4Len < 0 || l4 + l4Len > f.length) l4Len = f.length - l4;
        if (l4Len < 0) l4Len = 0;

        return build(timeMs, f, ipStart, totalLen, captured, l4, l4Len, proto,
                src, dst, firstFragment);
    }

    // ---------------------------------------------------------------- IPv6

    private static Packet parseV6(long timeMs, byte[] f, int ipStart) {
        if (f.length < ipStart + 40) return null;
        if ((u8(f, ipStart) >>> 4) != 6) return null;

        int payloadLen = u16(f, ipStart + 4);
        int next = u8(f, ipStart + 6);
        int totalLen = 40 + payloadLen;
        int off = ipStart + 40;
        int captured = f.length - ipStart;

        int l4 = off;
        int remaining = payloadLen;
        if (l4 + remaining > f.length) remaining = f.length - l4;
        boolean firstFragment = true;

        // Walk common extension headers so the transport header is found.
        for (int guard = 0; guard < 8; guard++) {
            if (!isExtension(next)) break;
            if (remaining < 8 || l4 + 8 > f.length) { next = -1; break; }
            int hdrLen;
            if (next == 44) {                       // fragment
                int fragField = u16(f, l4 + 2);
                if ((fragField & 0xFFF8) != 0) firstFragment = false;
                hdrLen = 8;
            } else if (next == 51) {                // authentication header
                hdrLen = (u8(f, l4 + 1) + 2) * 4;
            } else {                                // hop-by-hop / routing / dest
                hdrLen = (u8(f, l4 + 1) + 1) * 8;
            }
            if (hdrLen <= 0 || l4 + hdrLen > f.length) { next = -1; break; }
            next = u8(f, l4);
            l4 += hdrLen;
            remaining -= hdrLen;
            if (remaining < 0) remaining = 0;
        }
        if (next < 0) return null;

        String src = ipv6(f, ipStart + 8);
        String dst = ipv6(f, ipStart + 24);
        return build(timeMs, f, ipStart, totalLen, captured, l4, remaining, next,
                src, dst, firstFragment);
    }

    private static boolean isExtension(int proto) {
        switch (proto) {
            case 0:    // hop-by-hop options
            case 43:   // routing
            case 44:   // fragment
            case 51:   // authentication header
            case 60:   // destination options
            case 135:  // mobility
                return true;
            default:
                return false;
        }
    }

    // ------------------------------------------------------------ transport

    private static Packet build(long timeMs, byte[] f, int ipStart, int totalLen,
            int captured, int l4, int l4Len, int proto, String src, String dst,
            boolean firstFragment) {
        String protoName;
        String app = "";
        int srcPort = -1, dstPort = -1;
        int tcpFlags = -1;
        int payloadLen = 0;
        String host = "";
        String summary;

        if (!firstFragment) {
            // Non-first fragment: the bytes here are fragment payload, not a
            // transport header, so ports/flags cannot be read.
            protoName = proto == PROTO_TCP ? "TCP"
                    : proto == PROTO_UDP ? "UDP"
                    : proto == PROTO_ICMP ? "ICMP" : "OTHER";
            byte[] fragRaw = new byte[f.length];
            System.arraycopy(f, 0, fragRaw, 0, f.length);
            return new Packet(timeMs, totalLen > 0 ? totalLen : captured, captured,
                    src, dst, -1, -1, protoName, "", -1, l4Len,
                    String.format(Locale.US, "IP fragment proto=%d %s → %s len=%d",
                            proto, src, dst, l4Len), fragRaw);
        }

        switch (proto) {
            case PROTO_TCP: {
                protoName = "TCP";
                if (l4Len >= 20 && l4 + 20 <= f.length) {
                    srcPort = u16(f, l4);
                    dstPort = u16(f, l4 + 2);
                    int dataOff = (u8(f, l4 + 12) >>> 4) * 4;
                    tcpFlags = u8(f, l4 + 13);
                    int window = u16(f, l4 + 14);
                    int tcpPayload = l4Len - dataOff;
                    if (tcpPayload < 0) tcpPayload = 0;
                    payloadLen = tcpPayload;
                    if (firstFragment) {
                        app = appProtoTcp(f, l4 + dataOff, tcpPayload, srcPort, dstPort);
                        host = hostTcp(f, l4 + dataOff, tcpPayload);
                    }
                    summary = String.format(Locale.US,
                            "TCP %s:%d → %s:%d [%s] len=%d win=%d%s",
                            src, srcPort, dst, dstPort, flagText(tcpFlags), tcpPayload, window,
                            app.isEmpty() ? "" : "  " + app);
                } else {
                    summary = String.format(Locale.US, "TCP %s → %s len=%d", src, dst, l4Len);
                }
                break;
            }
            case PROTO_UDP: {
                protoName = "UDP";
                if (l4Len >= 8 && l4 + 8 <= f.length) {
                    srcPort = u16(f, l4);
                    dstPort = u16(f, l4 + 2);
                    int udpLen = u16(f, l4 + 4);
                    int udpPayload = udpLen - 8;
                    if (udpPayload < 0 || udpPayload > l4Len - 8) udpPayload = l4Len - 8;
                    if (udpPayload < 0) udpPayload = 0;
                    payloadLen = udpPayload;
                    if (firstFragment) {
                        app = appProtoUdp(f, l4 + 8, udpPayload, srcPort, dstPort);
                        if ("DNS".equals(app)) host = dnsQuestion(f, l4 + 8, udpPayload);
                    }
                    summary = String.format(Locale.US, "UDP %s:%d → %s:%d len=%d%s",
                            src, srcPort, dst, dstPort, udpPayload,
                            app.isEmpty() ? "" : "  " + app);
                } else {
                    summary = String.format(Locale.US, "UDP %s → %s len=%d", src, dst, l4Len);
                }
                break;
            }
            case PROTO_ICMP:
            case PROTO_ICMPV6: {
                protoName = proto == PROTO_ICMPV6 ? "ICMPv6" : "ICMP";
                int type = l4Len >= 1 && l4 < f.length ? u8(f, l4) : 0;
                payloadLen = Math.max(0, l4Len - 4);
                summary = String.format(Locale.US, "%s %s → %s type=%d len=%d",
                        protoName, src, dst, type, payloadLen);
                app = "ICMP";
                break;
            }
            default:
                protoName = "OTHER";
                payloadLen = l4Len;
                summary = String.format(Locale.US, "IP proto=%d %s → %s len=%d",
                        proto, src, dst, l4Len);
                break;
        }

        byte[] raw = new byte[f.length];
        System.arraycopy(f, 0, raw, 0, f.length);
        if (!host.isEmpty()) summary += " host=" + host;
        return new Packet(timeMs, totalLen > 0 ? totalLen : captured, captured,
                src, dst, srcPort, dstPort, protoName, app, tcpFlags, payloadLen,
                summary, raw, host, -1, "");
    }

    // ------------------------------------------------------- app protocol

    private static String appProtoTcp(byte[] f, int p, int len, int sport, int dport) {
        if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080
                || sport == 8000 || dport == 8000 || sport == 8888 || dport == 8888) {
            return "HTTP";
        }
        if (sport == 443 || dport == 443 || sport == 8443 || dport == 8443) {
            return "TLS";
        }
        if (sport == 22 || dport == 22) return "SSH";
        if (sport == 53 || dport == 53) return "DNS/TCP";
        if (sport == 853 || dport == 853) return "DoT";
        if (len >= 4 && p + 4 <= f.length) {
            char a = (char) u8(f, p), b = (char) u8(f, p + 1);
            char c = (char) u8(f, p + 2), d = (char) u8(f, p + 3);
            if ((a == 'G' && b == 'E' && c == 'T' && d == ' ')
                    || (a == 'P' && b == 'O' && c == 'S' && d == 'T')
                    || (a == 'H' && b == 'E' && c == 'A' && d == 'D')
                    || (a == 'P' && b == 'U' && c == 'T' && d == ' ')
                    || (a == 'D' && b == 'E' && c == 'L' && d == 'E')) {
                return "HTTP";
            }
            if (a == 'H' && b == 'T' && c == 'T' && d == 'P') return "HTTP";
            if (u8(f, p) == 0x16) return "TLS";
        }
        return "";
    }

    private static String appProtoUdp(byte[] f, int p, int len, int sport, int dport) {
        if (sport == 53 || dport == 53) return "DNS";
        if (sport == 5353 || dport == 5353) return "mDNS";
        if (sport == 1900 || dport == 1900) return "SSDP";
        if (sport == 67 || dport == 67 || sport == 68 || dport == 68) return "DHCP";
        if (sport == 123 || dport == 123) return "NTP";
        if (sport == 443 || dport == 443) return "QUIC";
        if (sport == 5355 || dport == 5355) return "LLMNR";
        if (sport == 137 || dport == 137 || sport == 138 || dport == 138) return "NetBIOS";
        if (sport == 546 || dport == 546 || sport == 547 || dport == 547) return "DHCPv6";
        return "";
    }

    // ------------------------------------------------------ host metadata

    /** Extract HTTP Host or TLS ClientHello SNI when visible in this segment. */
    static String hostTcp(byte[] f, int p, int len) {
        if (f == null || p < 0 || len <= 0 || p >= f.length) return "";
        int end = Math.min(f.length, p + len);
        if (end - p >= 5 && u8(f, p) == 0x16) return tlsServerName(f, p, end);
        int limit = Math.min(end, p + 8192);
        String text = new String(f, p, limit - p, java.nio.charset.StandardCharsets.ISO_8859_1);
        String[] lines = text.split("\\r?\\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0 && "host".equalsIgnoreCase(line.substring(0, colon).trim())) {
                String value = line.substring(colon + 1).trim();
                int port = value.lastIndexOf(':');
                if (port > 0 && value.indexOf(']') < 0 && value.indexOf(':') == port)
                    value = value.substring(0, port);
                return cleanHost(value);
            }
        }
        return "";
    }

    private static String tlsServerName(byte[] f, int p, int end) {
        int recordEnd = Math.min(end, p + 5 + u16(f, p + 3));
        int h = p + 5;
        if (h + 4 > recordEnd || u8(f, h) != 1) return "";
        int helloEnd = Math.min(recordEnd, h + 4
                + ((u8(f, h + 1) << 16) | (u8(f, h + 2) << 8) | u8(f, h + 3)));
        int q = h + 4 + 2 + 32;
        if (q >= helloEnd) return "";
        q += 1 + u8(f, q);                         // session ID
        if (q + 2 > helloEnd) return "";
        int ciphers = u16(f, q); q += 2 + ciphers;
        if (q >= helloEnd) return "";
        q += 1 + u8(f, q);                         // compression methods
        if (q + 2 > helloEnd) return "";
        int extEnd = Math.min(helloEnd, q + 2 + u16(f, q));
        q += 2;
        while (q + 4 <= extEnd) {
            int type = u16(f, q);
            int size = u16(f, q + 2);
            int data = q + 4;
            int next = data + size;
            if (next > extEnd) return "";
            if (type == 0 && size >= 5) {         // server_name extension
                int listEnd = Math.min(next, data + 2 + u16(f, data));
                int n = data + 2;
                while (n + 3 <= listEnd) {
                    int nameType = u8(f, n++);
                    int nameLen = u16(f, n); n += 2;
                    if (n + nameLen > listEnd) return "";
                    if (nameType == 0 && nameLen > 0)
                        return cleanHost(new String(f, n, nameLen,
                                java.nio.charset.StandardCharsets.US_ASCII));
                    n += nameLen;
                }
            }
            q = next;
        }
        return "";
    }

    /** DNS question QNAME (first question only); compressed names are rejected. */
    static String dnsQuestion(byte[] f, int p, int len) {
        int end = Math.min(f.length, p + len);
        if (p < 0 || p + 12 > end || u16(f, p + 4) == 0) return "";
        int q = p + 12;
        StringBuilder name = new StringBuilder();
        for (int labels = 0; labels < 127 && q < end; labels++) {
            int n = u8(f, q++);
            if (n == 0) return cleanHost(name.toString());
            if ((n & 0xC0) != 0 || n > 63 || q + n > end) return "";
            if (name.length() > 0) name.append('.');
            name.append(new String(f, q, n, java.nio.charset.StandardCharsets.US_ASCII));
            q += n;
        }
        return "";
    }

    private static String cleanHost(String value) {
        if (value == null) return "";
        String host = value.trim().toLowerCase(Locale.US);
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || host.length() > 253 || host.indexOf(' ') >= 0
                || host.indexOf('/') >= 0 || host.indexOf('\\') >= 0) return "";
        return host;
    }

    // ------------------------------------------------------------- helpers

    private static String flagText(int flags) {
        StringBuilder b = new StringBuilder();
        if ((flags & 0x01) != 0) b.append("FIN,");
        if ((flags & 0x02) != 0) b.append("SYN,");
        if ((flags & 0x04) != 0) b.append("RST,");
        if ((flags & 0x08) != 0) b.append("PSH,");
        if ((flags & 0x10) != 0) b.append("ACK,");
        if ((flags & 0x20) != 0) b.append("URG,");
        if ((flags & 0x40) != 0) b.append("ECE,");
        if ((flags & 0x80) != 0) b.append("CWR,");
        if (b.length() > 0) b.setLength(b.length() - 1);
        return b.toString();
    }

    private static int u8(byte[] b, int i) { return b[i] & 0xFF; }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    private static String ipv4(byte[] b, int o) {
        return (b[o] & 0xFF) + "." + (b[o + 1] & 0xFF) + "."
                + (b[o + 2] & 0xFF) + "." + (b[o + 3] & 0xFF);
    }

    /** RFC 5952-style compressed IPv6 text for display. */
    static String ipv6(byte[] b, int o) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((b[o + i * 2] & 0xFF) << 8) | (b[o + i * 2 + 1] & 0xFF);

        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (g[i] == 0) {
                if (curStart < 0) curStart = i;
                curLen++;
                if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }
        if (bestLen < 2) { bestStart = -1; bestLen = 0; }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') sb.append(':');
            sb.append(Integer.toHexString(g[i]));
        }
        if (sb.length() == 0) return "::";
        return sb.toString();
    }
}
