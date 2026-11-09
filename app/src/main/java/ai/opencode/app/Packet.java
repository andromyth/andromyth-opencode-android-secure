package ai.opencode.app;

/** One captured IP packet and best-effort application metadata. */
public final class Packet {
    public final long timeMs;
    public final int length;
    public final int capturedLen;
    public final String srcIp;
    public final String dstIp;
    public final int srcPort;
    public final int dstPort;
    public final String proto;
    public final String appProto;
    public final int tcpFlags;
    public final int payloadLen;
    public final String summary;
    public final byte[] raw;
    /** Cleartext hostname metadata only; encrypted payload is never decrypted. */
    public final String host;
    /** -1 means Android could not map this flow to an application UID. */
    public final int ownerUid;
    /** Package names may be comma-separated for shared UIDs. */
    public final String ownerPackages;

    public Packet(long timeMs, int length, int capturedLen, String srcIp, String dstIp,
            int srcPort, int dstPort, String proto, String appProto, int tcpFlags,
            int payloadLen, String summary, byte[] raw) {
        this(timeMs, length, capturedLen, srcIp, dstIp, srcPort, dstPort, proto,
                appProto, tcpFlags, payloadLen, summary, raw, "", -1, "");
    }

    public Packet(long timeMs, int length, int capturedLen, String srcIp, String dstIp,
            int srcPort, int dstPort, String proto, String appProto, int tcpFlags,
            int payloadLen, String summary, byte[] raw, String host,
            int ownerUid, String ownerPackages) {
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
        this.host = host == null ? "" : host;
        this.ownerUid = ownerUid;
        this.ownerPackages = ownerPackages == null ? "" : ownerPackages;
    }

    public Packet withOwner(int uid, String packages) {
        return new Packet(timeMs, length, capturedLen, srcIp, dstIp, srcPort,
                dstPort, proto, appProto, tcpFlags, payloadLen, summary, raw,
                host, uid, packages);
    }

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
