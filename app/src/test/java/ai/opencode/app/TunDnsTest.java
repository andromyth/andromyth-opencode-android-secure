package ai.opencode.app;

import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.*;

public class TunDnsTest {

    private static byte[] query(String name, int type) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x12);
        o.write(0x34);
        o.write(0x01);
        o.write(0x00);
        o.write(0x00);
        o.write(0x01);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
        o.write((type >> 8) & 0xff);
        o.write(type & 0xff);
        o.write(0);
        o.write(1);
        return o.toByteArray();
    }

    @Test public void parsesNameTypeAndEnd() {
        byte[] q = query("Example.COM", 1);
        TunDns.Q parsed = TunDns.parseQuestion(q, 0, q.length);
        assertNotNull(parsed);
        assertEquals("example.com", parsed.name);
        assertEquals(1, parsed.type);
        assertEquals(q.length, parsed.end);
    }

    @Test public void rejectsCompressedAndShort() {
        assertNull(TunDns.parseQuestion(new byte[10], 0, 10));
        byte[] q = query("a.com", 28);
        q[12] = (byte) 0xc0;
        assertNull(TunDns.parseQuestion(q, 0, q.length));
    }

    @Test public void errorEchoesQuestionWithRcode() {
        byte[] q = query("down.example", 1);
        byte[] e = TunDns.dnsError(q, q.length, 2);
        assertNotNull(e);
        assertEquals(q.length, e.length);
        int flags = TunDns.u16(e, 2);
        assertTrue((flags & 0x8000) != 0);
        assertEquals(2, flags & 0xf);
        assertEquals(1, TunDns.u16(e, 4));
        assertEquals(0, TunDns.u16(e, 6));
    }

    @Test public void buildsValidIpv4Reply() {
        byte[] q = query("example.com", 1);
        byte[] reply = TunDns.reply4(new byte[]{10, 0, 0, 9}, 5353, q);
        assertEquals(20 + 8 + q.length, reply.length);
        assertEquals(0x45, reply[0] & 0xff);
        assertEquals(17, reply[9] & 0xff);
        assertArrayEquals(new byte[]{10, 0, 0, 9}, new byte[]{reply[16], reply[17], reply[18], reply[19]});
        assertEquals(53, TunDns.u16(reply, 20));
        assertEquals(5353, TunDns.u16(reply, 22));
        assertEquals(0, TunDns.checksum(reply, 0, 20));
        assertNotEquals(0, TunDns.u16(reply, 26));
    }

    private static int verifyUdp4(byte[] p) {
        int ihl = (p[0] & 0xf) * 4;
        int ulen = TunDns.u16(p, ihl + 4);
        long s = 0;
        for (int i = 12; i < 20; i += 2) s += TunDns.u16(p, i);
        s += 0x0011;
        s += ulen;
        int end = ihl + ulen;
        int i = ihl;
        for (; i + 1 < end; i += 2) s += TunDns.u16(p, i);
        if (i < end) s += (p[i] & 0xff) << 8;
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s) & 0xffff;
    }

    private static int verifyUdp6(byte[] p) {
        int ulen = TunDns.u16(p, 44);
        long s = 0;
        for (int i = 8; i < 40; i += 2) s += TunDns.u16(p, i);
        s += (ulen >> 16) & 0xffff;
        s += ulen & 0xffff;
        s += 0x0011;
        int end = 40 + ulen;
        int i = 40;
        for (; i + 1 < end; i += 2) s += TunDns.u16(p, i);
        if (i < end) s += (p[i] & 0xff) << 8;
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s) & 0xffff;
    }

    @Test public void ipv4UdpChecksumVerifies() {
        byte[] reply = TunDns.reply4(new byte[]{10, 0, 0, 9}, 5353, query("example.com", 1));
        assertEquals(0, verifyUdp4(reply));
    }

    @Test public void ipv6UdpChecksumVerifies() {
        byte[] src = new byte[16];
        src[0] = (byte) 0xfe;
        src[1] = (byte) 0x80;
        src[15] = 7;
        byte[] reply = TunDns.reply6(src, 5353, query("example.com", 28));
        assertEquals(0, verifyUdp6(reply));
    }

    @Test public void buildsValidIpv6Reply() {
        byte[] q = query("example.com", 28);
        byte[] src = new byte[16];
        src[0] = (byte) 0xfe;
        src[1] = (byte) 0x80;
        src[15] = 7;
        byte[] reply = TunDns.reply6(src, 5353, q);
        assertEquals(40 + 8 + q.length, reply.length);
        assertEquals(0x60, reply[0] & 0xff);
        assertEquals(17, reply[6] & 0xff);
        assertEquals(53, TunDns.u16(reply, 40));
        assertEquals(5353, TunDns.u16(reply, 42));
        assertEquals(src[15], reply[39]);
        assertNotEquals(0, TunDns.u16(reply, 46));
    }
}
