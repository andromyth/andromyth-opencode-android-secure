package ai.opencode.app;

/** One captured IP packet, dissected enough for a wireshark-style summary
 *  line plus the sniffnet-style statistics the capture UI aggregates.
 *
 *  <p>Frames captured through a {@code VpnService} tun descriptor are RAW IP
 *  packets (no Ethernet header); frames captured elsewhere may carry an
 *  Ethernet header. {@link PacketParser} normalizes both before building a
 *  {@code Packet}, and {@link PcapWriter} writes {@link #raw} as-is. */
public final class Packet {
    public final long timeMs;
    public final int length;        // IPv4/IPv6 total length
    public final int capturedLen;   // bytes actually captured
    public final String srcIp;
    public final String dstIp;
    public final int srcPort;       // -1 when the transport has no ports
    public final int dstPort;       // -1 when the transport has no ports
    public final String proto;      // TCP / UDP / ICMP / ICMPv6 / OTHER
    public final String appProto;   // HTTP / TLS / DNS / … or "" when unknown
    public final int tcpFlags;      // TCP flag byte, -1 when not TCP
    public final int payloadLen;    // transport payload bytes (not headers)
    public final String summary;    // human dissection line
    public final byte[] raw;        // captured frame, written verbatim to pcap

    public Packet(long timeMs, int length, int capturedLen, String srcIp, String dstIp,
            int srcPort, int dstPort, String proto, String appProto, int tcpFlags,
            int payloadLen, String summary, byte[] raw) {
        this.timeMs = timeMs;
        this.length = length;
        this.capturedLen = capturedLen;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.proto = proto;
        this.appProto = appProto == null ? "" : appProto;
        this.tcpFlags = tcpFlags;
        this.payloadLen = payloadLen;
        this.summary = summary;
        this.raw = raw;
    }

    /** Human TCP flag string ("SYN, ACK", …) or "" for non-TCP packets. */
    public String tcpFlagText() {
        if (tcpFlags < 0) return "";
        StringBuilder b = new StringBuilder();
        int f = tcpFlags;
        if ((f & 0x01) != 0) b.append("FIN, ");
        if ((f & 0x02) != 0) b.append("SYN, ");
        if ((f & 0x04) != 0) b.append("RST, ");
        if ((f & 0x08) != 0) b.append("PSH, ");
        if ((f & 0x10) != 0) b.append("ACK, ");
        if ((f & 0x20) != 0) b.append("URG, ");
        if ((f & 0x40) != 0) b.append("ECE, ");
        if ((f & 0x80) != 0) b.append("CWR, ");
        if (b.length() >= 2) b.setLength(b.length() - 2);
        return b.toString();
    }
}
