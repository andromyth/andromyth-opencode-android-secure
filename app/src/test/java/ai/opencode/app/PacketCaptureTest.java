package ai.opencode.app;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * P61 — the packet-capture pipeline on the JVM: raw-IP frames exactly as a
 * VpnService tun descriptor delivers them, Ethernet-wrapped frames, IPv6,
 * TCP flag decoding, app-protocol hints, and pcap output. No Android APIs.
 */
public class PacketCaptureTest {

    // ---------------------------------------------------------- frame builders

    private static byte[] ipv4Tcp(byte[] payloadContent, int sport, int dport, int flags) {
        int tcpLen = 20 + payloadContent.length;
        byte[] f = new byte[20 + tcpLen];
        f[0] = 0x45;                 // IPv4, IHL 5
        int total = f.length;
        f[2] = (byte) (total >>> 8);
        f[3] = (byte) total;
        f[8] = 64;                   // TTL
        f[9] = 6;                    // TCP
        f[12] = 10; f[13] = 0; f[14] = 0; f[15] = 1;
        f[16] = 1; f[17] = 1; f[18] = 1; f[19] = 1;

        int t = 20;
        f[t] = (byte) (sport >>> 8); f[t + 1] = (byte) sport;
        f[t + 2] = (byte) (dport >>> 8); f[t + 3] = (byte) dport;
        f[t + 12] = 0x50;            // data offset 5 words
        f[t + 13] = (byte) flags;
        f[t + 14] = (byte) (64240 >>> 8); f[t + 15] = (byte) 64240;
        System.arraycopy(payloadContent, 0, f, 20 + 20, payloadContent.length);
        return f;
    }

    private static byte[] dnsQuestion(String hostname) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(0x12); out.write(0x34); out.write(0x01); out.write(0x00);
        out.write(0x00); out.write(0x01); out.write(0x00); out.write(0x00);
        out.write(0x00); out.write(0x00); out.write(0x00); out.write(0x00);
        for (String label : hostname.split("\\.")) {
            byte[] bytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.write(bytes.length); out.write(bytes, 0, bytes.length);
        }
        out.write(0); out.write(0); out.write(1); out.write(0); out.write(1);
        return out.toByteArray();
    }

    private static byte[] tlsClientHello(String hostname) {
        byte[] name = hostname.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int sniDataLen = 2 + 1 + 2 + name.length;
        int extLen = 4 + sniDataLen;
        int bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen;
        int handshakeLen = 4 + bodyLen;
        byte[] b = new byte[5 + handshakeLen];
        int p = 0;
        b[p++] = 0x16; b[p++] = 0x03; b[p++] = 0x01;
        b[p++] = (byte) (handshakeLen >>> 8); b[p++] = (byte) handshakeLen;
        b[p++] = 0x01;
        b[p++] = (byte) (bodyLen >>> 16); b[p++] = (byte) (bodyLen >>> 8);
        b[p++] = (byte) bodyLen;
        b[p++] = 0x03; b[p++] = 0x03;                  // legacy version
        p += 32;                                       // random
        b[p++] = 0;                                    // session id
        b[p++] = 0; b[p++] = 2; b[p++] = 0x13; b[p++] = 0x01;
        b[p++] = 1; b[p++] = 0;                        // compression
        b[p++] = (byte) (extLen >>> 8); b[p++] = (byte) extLen;
        b[p++] = 0; b[p++] = 0;                        // SNI extension
        b[p++] = (byte) (sniDataLen >>> 8); b[p++] = (byte) sniDataLen;
        int listLen = 3 + name.length;
        b[p++] = (byte) (listLen >>> 8); b[p++] = (byte) listLen;
        b[p++] = 0;                                    // host_name
        b[p++] = (byte) (name.length >>> 8); b[p++] = (byte) name.length;
        System.arraycopy(name, 0, b, p, name.length);
        return b;
    }

    private static byte[] ipv4Udp(int sport, int dport, byte[] payloadContent) {
        int udpLen = 8 + payloadContent.length;
        byte[] f = new byte[20 + udpLen];
        f[0] = 0x45;
        int total = f.length;
        f[2] = (byte) (total >>> 8); f[3] = (byte) total;
        f[8] = 64;
        f[9] = 17;                   // UDP
        f[12] = (byte) 192; f[13] = (byte) 168; f[14] = 1; f[15] = 2;
        f[16] = 8; f[17] = 8; f[18] = 8; f[19] = 8;

        int u = 20;
        f[u] = (byte) (sport >>> 8); f[u + 1] = (byte) sport;
        f[u + 2] = (byte) (dport >>> 8); f[u + 3] = (byte) dport;
        f[u + 4] = (byte) (udpLen >>> 8); f[u + 5] = (byte) udpLen;
        System.arraycopy(payloadContent, 0, f, 20 + 8, payloadContent.length);
        return f;
    }

    private static byte[] ipv6Tcp(int sport, int dport, int flags) {
        byte[] f = new byte[40 + 20];
        f[0] = 0x60;                 // IPv6
        int payload = 20;
        f[4] = (byte) (payload >>> 8); f[5] = (byte) payload;
        f[6] = 6;                    // next header TCP
        f[7] = 64;                   // hop limit
        // src 2001:db8::1 (bytes 8..23)
        f[8] = 0x20; f[9] = 0x01; f[10] = 0x0d; f[11] = (byte) 0xb8;
        f[23] = 1;
        // dst 2001:db8::2 (bytes 24..39)
        f[24] = 0x20; f[25] = 0x01; f[26] = 0x0d; f[27] = (byte) 0xb8;
        f[39] = 2;

        int t = 40;
        f[t] = (byte) (sport >>> 8); f[t + 1] = (byte) sport;
        f[t + 2] = (byte) (dport >>> 8); f[t + 3] = (byte) dport;
        f[t + 12] = 0x50;
        f[t + 13] = (byte) flags;
        return f;
    }

    // ---------------------------------------------------------------- parsing

    @Test public void rawIpv4Tcp_isParsed_notRejectedAsEthernet() {
        // The VpnService hands us a raw IP packet: first byte 0x45. The old
        // parser read bytes 12-13 as an Ethernet type and dropped everything.
        Packet p = PacketParser.parse(1000L, ipv4Tcp(new byte[0], 12345, 443, 0x02));
        assertNotNull(p);
        assertEquals("TCP", p.proto);
        assertEquals("10.0.0.1", p.srcIp);
        assertEquals("1.1.1.1", p.dstIp);
        assertEquals(12345, p.srcPort);
        assertEquals(443, p.dstPort);
        assertEquals("SYN", p.tcpFlagText());
        assertEquals("TLS", p.appProto);
        assertTrue(p.summary.contains("→"));
    }

    @Test public void httpHostHeaderIsExtracted() {
        byte[] payload = "GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        Packet p = PacketParser.parse(1500L, ipv4Tcp(payload, 50000, 80, 0x18));
        assertNotNull(p);
        assertEquals("example.com", p.host);
        assertTrue(p.summary.contains("host=example.com"));
    }

    @Test public void tlsClientHelloSniIsExtractedWithoutDecryptingPayload() {
        byte[] payload = tlsClientHello("secure.example.org");
        Packet p = PacketParser.parse(1600L, ipv4Tcp(payload, 50000, 443, 0x18));
        assertNotNull(p);
        assertEquals("TLS", p.appProto);
        assertEquals("secure.example.org", p.host);
    }

    @Test public void dnsQuestionNameIsExtracted() {
        byte[] payload = dnsQuestion("api.example.net");
        Packet p = PacketParser.parse(1700L, ipv4Udp(53000, 53, payload));
        assertNotNull(p);
        assertEquals("DNS", p.appProto);
        assertEquals("api.example.net", p.host);
    }

    @Test public void rawIpv4Udp_dnsDetected() {
        Packet p = PacketParser.parse(2000L, ipv4Udp(54321, 53, new byte[]{0, 1, 2, 3}));
        assertNotNull(p);
        assertEquals("UDP", p.proto);
        assertEquals(53, p.dstPort);
        assertEquals("DNS", p.appProto);
        assertEquals(4, p.payloadLen);
    }

    @Test public void ethernetWrappedIpv4_stillParsed() {
        byte[] ip = ipv4Tcp(new byte[0], 5555, 80, 0x18);
        byte[] eth = new byte[14 + ip.length];
        eth[12] = 0x08; eth[13] = 0x00;   // IPv4 ethertype
        System.arraycopy(ip, 0, eth, 14, ip.length);
        Packet p = PacketParser.parse(3000L, eth);
        assertNotNull(p);
        assertEquals("TCP", p.proto);
        assertEquals("HTTP", p.appProto);
        assertEquals(80, p.dstPort);
    }

    @Test public void rawIpv6Tcp_isParsed() {
        Packet p = PacketParser.parse(4000L, ipv6Tcp(4444, 443, 0x10));
        assertNotNull(p);
        assertEquals("TCP", p.proto);
        assertEquals(443, p.dstPort);
        assertEquals("TLS", p.appProto);
        assertTrue(p.srcIp.startsWith("2001:db8"));
        assertEquals("ACK", p.tcpFlagText());
    }

    @Test public void garbageAndTruncatedFramesAreDropped() {
        assertNull(PacketParser.parse(0L, null));
        assertNull(PacketParser.parse(0L, new byte[0]));
        assertNull(PacketParser.parse(0L, new byte[]{1, 2, 3}));
        assertNull(PacketParser.parse(0L, new byte[40]));       // version 0
        // Ethernet with a non-IP ethertype
        byte[] arp = new byte[14 + 20];
        arp[12] = 0x08; arp[13] = 0x06;
        assertNull(PacketParser.parse(0L, arp));
    }

    // ------------------------------------------------------------------ pcap

    @Test public void pcapHeaderAndRecordsAreWellFormed() throws Exception {
        List<Packet> list = new ArrayList<>();
        list.add(PacketParser.parse(1_700_000_000_500L, ipv4Tcp(new byte[0], 1234, 443, 0x02)));
        list.add(PacketParser.parse(1_700_000_001_250L, ipv4Udp(5353, 5353, new byte[4])));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PcapWriter.write(out, list);
        byte[] b = out.toByteArray();

        // Global header: 24 bytes, magic d4 c3 b2 a1 (little-endian).
        assertTrue(b.length > 24);
        assertEquals(0xD4, b[0] & 0xFF);
        assertEquals(0xC3, b[1] & 0xFF);
        assertEquals(0xB2, b[2] & 0xFF);
        assertEquals(0xA1, b[3] & 0xFF);
        assertEquals(2, b[4] & 0xFF);           // version major
        assertEquals(4, b[6] & 0xFF);           // version minor
        // network = LINKTYPE_RAW (101) at offset 20, little-endian
        assertEquals(101, (b[20] & 0xFF) | ((b[21] & 0xFF) << 8));

        // First record starts at 24; incl_len at +8 must equal the frame size.
        int incl = (b[24 + 8] & 0xFF) | ((b[24 + 9] & 0xFF) << 8)
                | ((b[24 + 10] & 0xFF) << 16) | ((b[24 + 11] & 0xFF) << 24);
        assertEquals(list.get(0).raw.length, incl);
    }

    @Test public void exportWritesAFileThatExists() throws Exception {
        File dir = Files.createTempDirectory("oc-pcap-test").toFile();
        List<Packet> list = new ArrayList<>();
        list.add(PacketParser.parse(System.currentTimeMillis(), ipv4Udp(1000, 53, new byte[2])));
        File f = PcapWriter.writeToDir(dir, "t.pcap", list);
        assertTrue(f.exists());
        assertTrue(f.length() > 24);
        //noinspection ResultOfMethodCallIgnored
        f.delete();
        //noinspection ResultOfMethodCallIgnored
        dir.delete();
    }
}
