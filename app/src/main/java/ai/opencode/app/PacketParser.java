package ai.opencode.app;

import java.util.Locale;

/** Wireshark-style dissection of a captured Ethernet/IPv4 frame. */
public final class PacketParser {

    private PacketParser() {}

    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    /** Parse one captured frame. Returns null when it is not a parseable
     *  IPv4 packet (e.g. a control frame the VPN service emitted). */
    public static Packet parse(long timeMs, byte[] frame) {
        if (frame == null || frame.length < 14 + 20) return null;
        // Ethernet header is 14 bytes; only IPv4 (0x0800) is dissected.
        int ethType = ((frame[12] & 0xFF) << 8) | (frame[13] & 0xFF);
        if (ethType != 0x0800) return null;
        int ipStart = 14;
        int versionIhl = frame[ipStart] & 0xFF;
        int version = versionIhl >>> 4;
        if (version != 4) return null;
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || ipStart + ihl > frame.length) return null;
        int totalLen = ((frame[ipStart + 2] & 0xFF) << 8) | (frame[ipStart + 3] & 0xFF);
        int proto = frame[ipStart + 9] & 0xFF;
        String srcIp = ip(frame, ipStart + 12);
        String dstIp = ip(frame, ipStart + 16);
        int payloadStart = ipStart + ihl;
        int payloadLen = totalLen - ihl;
        if (payloadLen < 0 || payloadStart + payloadLen > frame.length) {
            payloadLen = frame.length - payloadStart;
        }
        String protoName;
        int srcPort = -1, dstPort = -1;
        String summary;
        switch (proto) {
            case PROTO_TCP:
                protoName = "TCP";
                if (payloadLen >= 20) {
                    srcPort = ((frame[payloadStart] & 0xFF) << 8) | (frame[payloadStart + 1] & 0xFF);
                    dstPort = ((frame[payloadStart + 2] & 0xFF) << 8) | (frame[payloadStart + 3] & 0xFF);
                    int flags = frame[payloadStart + 13] & 0xFF;
                    summary = String.format(Locale.US, "TCP %s:%d → %s:%d len=%d flags=0x%02x",
                            srcIp, srcPort, dstIp, dstPort, payloadLen, flags);
                } else {
                    summary = String.format(Locale.US, "TCP %s → %s len=%d", srcIp, dstIp, payloadLen);
                }
                break;
            case PROTO_UDP:
                protoName = "UDP";
                if (payloadLen >= 8) {
                    srcPort = ((frame[payloadStart] & 0xFF) << 8) | (frame[payloadStart + 1] & 0xFF);
                    dstPort = ((frame[payloadStart + 2] & 0xFF) << 8) | (frame[payloadStart + 3] & 0xFF);
                    int udpLen = ((frame[payloadStart + 4] & 0xFF) << 8) | (frame[payloadStart + 5] & 0xFF);
                    summary = String.format(Locale.US, "UDP %s:%d → %s:%d len=%d",
                            srcIp, srcPort, dstIp, dstPort, udpLen);
                } else {
                    summary = String.format(Locale.US, "UDP %s → %s len=%d", srcIp, dstIp, payloadLen);
                }
                break;
            case PROTO_ICMP:
                protoName = "ICMP";
                int icmpType = payloadStart < frame.length ? (frame[payloadStart] & 0xFF) : 0;
                summary = String.format(Locale.US, "ICMP %s → %s type=%d len=%d",
                        srcIp, dstIp, icmpType, payloadLen);
                break;
            default:
                protoName = "OTHER";
                summary = String.format(Locale.US, "IP proto=%d %s → %s len=%d",
                        proto, srcIp, dstIp, payloadLen);
                break;
        }
        byte[] raw = new byte[frame.length];
        System.arraycopy(frame, 0, raw, 0, frame.length);
        return new Packet(timeMs, totalLen > 0 ? totalLen : frame.length,
                srcIp, dstIp, srcPort, dstPort, protoName, summary, raw);
    }

    private static String ip(byte[] frame, int off) {
        return (frame[off] & 0xFF) + "." + (frame[off + 1] & 0xFF) + "."
                + (frame[off + 2] & 0xFF) + "." + (frame[off + 3] & 0xFF);
    }
}
