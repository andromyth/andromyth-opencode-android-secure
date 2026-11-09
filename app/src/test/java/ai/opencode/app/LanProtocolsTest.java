package ai.opencode.app;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * P61 — the wire formats behind non-root LAN discovery. Every encoder and
 * parser is exercised with synthetic packets on the JVM, so no socket, no
 * multicast lock and no live LAN are involved.
 */
public class LanProtocolsTest {

    // ------------------------------------------------------------- helpers

    private static byte[] name(String n) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (String p : n.split("\\.")) {
            if (p.isEmpty()) continue;
            byte[] b = p.getBytes(StandardCharsets.ISO_8859_1);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
        return o.toByteArray();
    }

    private static void u16(ByteArrayOutputStream o, int v) {
        o.write((v >>> 8) & 0xFF);
        o.write(v & 0xFF);
    }

    private static void u32(ByteArrayOutputStream o, long v) {
        o.write((int) (v >>> 24) & 0xFF);
        o.write((int) (v >>> 16) & 0xFF);
        o.write((int) (v >>> 8) & 0xFF);
        o.write((int) v & 0xFF);
    }

    // ------------------------------------------------------------- encoders

    @Test public void mdnsQuery_isPtrWithUnicastResponseBit() {
        byte[] q = LanProtocols.mdnsQuery("_http._tcp.local");
        assertTrue(q.length > 12);
        assertEquals(0, q[0]);              // id 0
        assertEquals(0, q[1]);
        assertEquals(0, q[4]);              // qdcount high
        assertEquals(1, q[5]);
        int n = q.length;
        assertEquals(0, q[n - 4]);          // qtype = PTR (12)
        assertEquals(12, q[n - 3]);
        assertEquals(0x80, q[n - 2] & 0xFF); // QU bit set
        assertEquals(1, q[n - 1]);
        String text = new String(q, StandardCharsets.ISO_8859_1);
        assertTrue(text.contains("_http"));
        assertTrue(text.contains("_tcp"));
    }

    @Test public void ssdpSearch_isWellFormed() {
        String s = new String(LanProtocols.ssdpSearch(),
                StandardCharsets.ISO_8859_1);
        assertTrue(s.startsWith("M-SEARCH * HTTP/1.1\r\n"));
        assertTrue(s.contains("MAN: \"ssdp:discover\""));
        assertTrue(s.contains("ST: ssdp:all"));
        assertTrue(s.endsWith("\r\n\r\n"));
    }

    @Test public void ptrQuery_reversesOctets() {
        byte[] q = LanProtocols.ptrQuery("10.51.134.43");
        String s = new String(q, StandardCharsets.ISO_8859_1);
        assertTrue(s.contains("43"));
        assertTrue(s.contains("134"));
        assertTrue(s.contains("in-addr"));
        assertTrue(s.contains("arpa"));
        assertEquals(12, q[q.length - 3]);  // PTR
    }

    @Test public void nbnsQuery_hasNBSTATType() {
        byte[] q = LanProtocols.nbnsStatusQuery();
        assertEquals(0x12, q[0] & 0xFF);
        assertEquals(0x34, q[1] & 0xFF);
        assertEquals(1, q[5]);              // qdcount
        assertEquals(0x20, q[12] & 0xFF);   // 32-char NetBIOS label
        int n = q.length;
        assertEquals(0x00, q[n - 4] & 0xFF);
        assertEquals(0x21, q[n - 3] & 0xFF); // NBSTAT
        assertEquals(0x00, q[n - 2] & 0xFF);
        assertEquals(0x01, q[n - 1] & 0xFF);
    }

    // -------------------------------------------------------------- parsers

    @Test public void parseSsdp_lowercasesHeaders() {
        String resp = "HTTP/1.1 200 OK\r\n"
                + "SERVER: Linux/3 UPnP/1.1\r\n"
                + "ST: upnp:rootdevice\r\n"
                + "USN: uuid:abc\r\n\r\n";
        Map<String, String> h = LanProtocols.parseSsdp(
                resp.getBytes(StandardCharsets.ISO_8859_1));
        assertEquals("HTTP/1.1 200 OK", h.get("_status"));
        assertEquals("Linux/3 UPnP/1.1", h.get("server"));
        assertEquals("upnp:rootdevice", h.get("st"));
        assertEquals("uuid:abc", h.get("usn"));
    }

    @Test public void parseDns_extractsPtrAAndTxt() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, 0); u16(o, 0x8400); u16(o, 0); u16(o, 3); u16(o, 0); u16(o, 0);
        byte[] owner = name("_http._tcp.local");

        o.write(owner, 0, owner.length);
        u16(o, 12); u16(o, 1); u32(o, 120);
        byte[] inst = name("Living Room TV._http._tcp.local");
        u16(o, inst.length); o.write(inst, 0, inst.length);

        o.write(owner, 0, owner.length);
        u16(o, 1); u16(o, 1); u32(o, 120); u16(o, 4);
        o.write(192); o.write(168); o.write(1); o.write(50);

        o.write(owner, 0, owner.length);
        u16(o, 16); u16(o, 1); u32(o, 120);
        byte[] txt = "model=SmartTV".getBytes(StandardCharsets.UTF_8);
        u16(o, txt.length + 1);
        o.write(txt.length); o.write(txt, 0, txt.length);

        LanProtocols.Dns d = LanProtocols.parseDns(o.toByteArray());
        assertNotNull(d);
        assertTrue(d.ptr.contains("Living Room TV._http._tcp.local"));
        assertTrue(d.ipv4.contains("192.168.1.50"));
        assertTrue(d.txt.contains("model=SmartTV"));
    }

    @Test public void parseDns_followsCompressionPointer() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, 0); u16(o, 0x8400); u16(o, 1); u16(o, 1); u16(o, 0); u16(o, 0);
        byte[] q = name("_services._dns-sd._udp.local");
        o.write(q, 0, q.length); u16(o, 12); u16(o, 1);

        o.write(0xC0); o.write(12);        // pointer to the question name
        u16(o, 12); u16(o, 1); u32(o, 120);
        byte[] val = name("_http._tcp.local");
        u16(o, val.length); o.write(val, 0, val.length);

        LanProtocols.Dns d = LanProtocols.parseDns(o.toByteArray());
        assertNotNull(d);
        assertEquals(1, d.questions.size());
        assertTrue(d.ptr.contains("_http._tcp.local"));
    }

    @Test public void parseNbns_extractsStationName() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, 0x1234); u16(o, 0x8400); u16(o, 0); u16(o, 1); u16(o, 0); u16(o, 0);
        o.write(0x20);
        for (int i = 0; i < 32; i++) o.write('A');
        o.write(0x00);
        u16(o, 0x21); u16(o, 0x0001); u32(o, 0);
        u16(o, 1 + 16 + 2);                // rdlength
        o.write(1);                        // one name
        StringBuilder nb = new StringBuilder("MYPC");
        while (nb.length() < 15) nb.append(' ');
        o.write(nb.toString().getBytes(StandardCharsets.ISO_8859_1), 0, 15);
        o.write(0x00);                     // suffix
        u16(o, 0x0400);                    // flags

        List<String> names = LanProtocols.parseNbns(o.toByteArray());
        assertTrue(names.contains("MYPC"));
    }

    @Test public void malformedPacketsDoNotThrow() {
        assertEquals(null, LanProtocols.parseDns(null));
        assertEquals(null, LanProtocols.parseDns(new byte[]{1, 2, 3}));
        assertTrue(LanProtocols.parseNbns(null).isEmpty());
        assertTrue(LanProtocols.parseNbns(new byte[]{1, 2}).isEmpty());
    }

    @Test public void serviceAndInstanceHelpers() {
        assertTrue(LanProtocols.isServiceType("_http._tcp.local"));
        assertFalse(LanProtocols.isServiceType(
                "Living Room TV._http._tcp.local"));
        assertEquals("Living Room TV", LanProtocols.instanceLabel(
                "Living Room TV._http._tcp.local."));
        assertEquals("host.local", LanProtocols.trimDot("host.local."));
        assertEquals("", LanProtocols.trimDot(null));
    }
}
