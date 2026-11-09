package ai.opencode.app;

import java.util.Locale;

public final class TunDns {

    private TunDns() {}

    public static final String DNS4 = "10.111.222.1";
    public static final String DNS6 = "fd00:6f70:656e:3a3a::1";

    static final byte[] DNS4_BYTES = {(byte) 10, (byte) 111, (byte) 222, 1};
    static final byte[] DNS6_BYTES = {
            (byte) 0xfd, 0x00, 0x6f, 0x70, 0x65, 0x6e, 0x3a, 0x3a,
            0, 0, 0, 0, 0, 0, 0, 1
    };

    public static final class Q {
        public final String name;
        public final int type;
        public final int end;

        Q(String name, int type, int end) {
            this.name = name;
            this.type = type;
            this.end = end;
        }
    }

    static int u16(byte[] b, int o) {
        return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff);
    }

    static void p16(byte[] b, int o, int v) {
        b[o] = (byte) (v >> 8);
        b[o + 1] = (byte) v;
    }

    public static Q parseQuestion(byte[] b, int off, int end) {
        if (b == null || off < 0 || end > b.length || end - off < 12) return null;
        if (u16(b, off + 4) < 1) return null;
        int p = off + 12;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (p >= end) return null;
            int len = b[p++] & 0xff;
            if (len == 0) break;
            if ((len & 0xc0) != 0) return null;
            if (p + len > end) return null;
            if (sb.length() + len > 253) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < len; i++) {
                int c = b[p + i] & 0xff;
                if (c <= 0x20 || c >= 0x7f) return null;
                sb.append((char) c);
            }
            p += len;
        }
        if (p + 4 > end) return null;
        String name = sb.toString().toLowerCase(Locale.US);
        if (name.isEmpty()) return null;
        return new Q(name, u16(b, p), p + 4);
    }

    public static byte[] dnsError(byte[] dns, int len, int rcode) {
        if (dns == null || len < 12 || len > dns.length) return null;
        int flags = u16(dns, 2);
        byte[] out = new byte[len];
        System.arraycopy(dns, 0, out, 0, len);
        p16(out, 2, (flags & 0x0110) | 0x8080 | (rcode & 0xf));
        p16(out, 6, 0);
        p16(out, 8, 0);
        p16(out, 10, 0);
        return out;
    }

    public static byte[] reply4(byte[] src4, int sport, byte[] payload) {
        int plen = payload == null ? 0 : payload.length;
        int total = 20 + 8 + plen;
        byte[] p = new byte[total];
        p[0] = 0x45;
        p16(p, 2, total);
        p16(p, 6, 0x4000);
        p[8] = 64;
        p[9] = 17;
        System.arraycopy(DNS4_BYTES, 0, p, 12, 4);
        System.arraycopy(src4, 0, p, 16, 4);
        p16(p, 20, 53);
        p16(p, 22, sport);
        p16(p, 24, 8 + plen);
        if (plen > 0) System.arraycopy(payload, 0, p, 28, plen);
        p16(p, 10, checksum(p, 0, 20));
        int uc = udp4Checksum(p, 20, 8 + plen);
        p16(p, 26, uc == 0 ? 0xffff : uc);
        return p;
    }

    public static byte[] reply6(byte[] src16, int sport, byte[] payload) {
        int plen = payload == null ? 0 : payload.length;
        int total = 40 + 8 + plen;
        byte[] p = new byte[total];
        p[0] = 0x60;
        p16(p, 4, 8 + plen);
        p[6] = 17;
        p[7] = 64;
        System.arraycopy(DNS6_BYTES, 0, p, 8, 16);
        System.arraycopy(src16, 0, p, 24, 16);
        p16(p, 40, 53);
        p16(p, 42, sport);
        p16(p, 44, 8 + plen);
        if (plen > 0) System.arraycopy(payload, 0, p, 48, plen);
        int uc = udp6Checksum(p, 40, 8 + plen);
        p16(p, 46, uc == 0 ? 0xffff : uc);
        return p;
    }

    static int checksum(byte[] b, int off, int len) {
        return finish(sum(0, b, off, len));
    }

    private static long sum(long s, byte[] b, int off, int len) {
        int end = off + len;
        int i = off;
        while (i + 1 < end) {
            s += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) s += (b[i] & 0xff) << 8;
        return s;
    }

    private static int finish(long s) {
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s) & 0xffff;
    }

    private static int udp4Checksum(byte[] p, int uoff, int ulen) {
        long s = sum(0, p, 12, 8);
        s += 0x0011;
        s += ulen;
        s = sum(s, p, uoff, ulen);
        return finish(s);
    }

    private static int udp6Checksum(byte[] p, int uoff, int ulen) {
        long s = sum(0, p, 8, 32);
        s += (ulen >> 16) & 0xffff;
        s += ulen & 0xffff;
        s += 0x0011;
        s = sum(s, p, uoff, ulen);
        return finish(s);
    }
}
