package ai.opencode.app;

/** One captured IP packet, dissected enough for a wireshark-style summary line. */
public final class Packet {
    public final long timeMs;
    public final int length;
    public final String srcIp;
    public final String dstIp;
    public final int srcPort;
    public final int dstPort;
    public final String proto;      // TCP / UDP / ICMP / OTHER
    public final String summary;    // human dissection line
    public final byte[] raw;        // captured frame

    public Packet(long timeMs, int length, String srcIp, String dstIp,
            int srcPort, int dstPort, String proto, String summary, byte[] raw) {
        this.timeMs = timeMs;
        this.length = length;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.proto = proto;
        this.summary = summary;
        this.raw = raw;
    }
}
