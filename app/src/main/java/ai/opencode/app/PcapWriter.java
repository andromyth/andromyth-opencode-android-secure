package ai.opencode.app;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Writes captured packets as a classic libpcap file so the result opens
 * directly in Wireshark, tshark, tcpdump, or Sniffnet.
 *
 * <p>Android's {@code VpnService} hands back raw IP packets, so the link type
 * is {@code LINKTYPE_RAW} (101); if a frame already carries an Ethernet
 * header the link type becomes {@code LINKTYPE_ETHERNET} (1). No third-party
 * libraries, no Android APIs — pure java.io, so it is unit-testable on the
 * JVM.
 */
public final class PcapWriter {

    private PcapWriter() {}

    public static final int LINKTYPE_ETHERNET = 1;
    public static final int LINKTYPE_RAW = 101;

    private static final int SNAPLEN = 262144;

    /** Default file name: {@code capture-20261109-081500.pcap}. */
    public static String defaultName() {
        return "capture-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
                .format(new Date()) + ".pcap";
    }

    /** Write {@code packets} into {@code dir/name}, creating {@code dir}. */
    public static File writeToDir(File dir, String name, List<Packet> packets)
            throws IOException {
        if (dir != null && !dir.exists() && !dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("cannot create " + dir);
        }
        File out = new File(dir, name);
        try (OutputStream os = new FileOutputStream(out)) {
            write(os, packets);
        }
        return out;
    }

    /** Write {@code packets} as a pcap stream (little-endian, 2.4 format). */
    public static void write(OutputStream out, List<Packet> packets) throws IOException {
        int linkType = LINKTYPE_RAW;
        for (Packet p : packets) {
            if (p.raw != null && p.raw.length > 0) {
                int hi = p.raw[0] & 0xF0;
                if (hi != 0x40 && hi != 0x60) linkType = LINKTYPE_ETHERNET;
                break;
            }
        }

        ByteBuf h = new ByteBuf(24);
        h.u32(0xA1B2C3D4L);   // magic (LE on disk)
        h.u16(2);             // version major
        h.u16(4);             // version minor
        h.u32(0);             // thiszone
        h.u32(0);             // sigfigs
        h.u32(SNAPLEN);       // snaplen
        h.u32(linkType);      // network
        h.writeTo(out);

        for (Packet p : packets) {
            byte[] raw = p.raw;
            if (raw == null) continue;
            long ms = p.timeMs;
            ByteBuf rec = new ByteBuf(16 + raw.length);
            rec.u32(ms / 1000L);              // ts_sec
            rec.u32((ms % 1000L) * 1000L);    // ts_usec
            rec.u32(raw.length);              // incl_len
            rec.u32(raw.length);              // orig_len
            rec.bytes(raw);
            rec.writeTo(out);
        }
        out.flush();
    }

    /** Tiny little-endian writer (pcap is LE on disk). */
    private static final class ByteBuf {
        private final byte[] buf;
        private int pos;

        ByteBuf(int size) { buf = new byte[size]; }

        void u16(int v) {
            buf[pos++] = (byte) (v & 0xFF);
            buf[pos++] = (byte) ((v >>> 8) & 0xFF);
        }

        void u32(long v) {
            buf[pos++] = (byte) (v & 0xFF);
            buf[pos++] = (byte) ((v >>> 8) & 0xFF);
            buf[pos++] = (byte) ((v >>> 16) & 0xFF);
            buf[pos++] = (byte) ((v >>> 24) & 0xFF);
        }

        void bytes(byte[] b) {
            System.arraycopy(b, 0, buf, pos, b.length);
            pos += b.length;
        }

        void writeTo(OutputStream out) throws IOException { out.write(buf, 0, pos); }
    }
}
