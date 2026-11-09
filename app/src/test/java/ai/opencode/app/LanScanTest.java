package ai.opencode.app;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * P60 — the non-root LAN scan contract, pinned without a network.
 *
 * The field failure this fixes: "find all connected devices" ended in a
 * dead end because the guest has no ip/arp/nmap and no CAP_NET_RAW. The
 * scan here uses only connect(), so it is a pure function of its prober
 * and can be tested on the JVM with a fake one — no sockets, no CI LAN.
 */
public class LanScanTest {

    // ----------------------------------------------------------- CIDR math

    @Test public void slash24_has254UsableHosts() {
        List<String> hosts = LanScan.candidateHosts("192.168.1.0/24");
        assertEquals(254, hosts.size());
        assertEquals("192.168.1.1", hosts.get(0));
        assertEquals("192.168.1.254", hosts.get(hosts.size() - 1));
        assertFalse(hosts.contains("192.168.1.0"));    // network
        assertFalse(hosts.contains("192.168.1.255"));  // broadcast
    }

    @Test public void slash25_staysInsideItsSubnet() {
        List<String> hosts = LanScan.candidateHosts("192.168.1.130/25");
        assertEquals(126, hosts.size());
        assertEquals("192.168.1.129", hosts.get(0));
        assertEquals("192.168.1.254", hosts.get(hosts.size() - 1));
    }

    @Test public void widePrefix_isNarrowedToOurSlash24() {
        List<String> hosts = LanScan.candidateHosts("10.5.7.9/16");
        assertEquals(LanScan.MAX_HOSTS, hosts.size());
        assertEquals("10.5.7.1", hosts.get(0));
        assertEquals("10.5.7.254", hosts.get(hosts.size() - 1));
    }

    @Test public void malformedCidr_isEmpty_notACrash() {
        assertTrue(LanScan.candidateHosts(null).isEmpty());
        assertTrue(LanScan.candidateHosts("").isEmpty());
        assertTrue(LanScan.candidateHosts("10.0.0.1").isEmpty());
        assertTrue(LanScan.candidateHosts("10.0.0.1/").isEmpty());
        assertTrue(LanScan.candidateHosts("10.0.0.1/33").isEmpty());
        assertTrue(LanScan.candidateHosts("10.0.0.999/24").isEmpty());
        assertTrue(LanScan.candidateHosts("nope/24").isEmpty());
    }

    @Test public void ipLongRoundTrips() {
        assertEquals(3232235777L, LanScan.ipToLong("192.168.1.1"));
        assertEquals("192.168.1.1", LanScan.longToIp(3232235777L));
        assertEquals(-1L, LanScan.ipToLong("256.0.0.1"));
        assertEquals(-1L, LanScan.ipToLong("1.2.3"));
    }

    @Test public void normalizeCidr_masksTheHostBits() {
        assertEquals("192.168.1.0/24", LanScan.normalizeCidr("192.168.1.130/24"));
        assertEquals("10.5.0.0/16", LanScan.normalizeCidr("10.5.7.9/16"));
        assertEquals("bad input", LanScan.normalizeCidr("bad input"));
    }

    @Test public void privateRanges_areRecognised() {
        assertTrue(LanScan.isPrivateOrLocal("192.168.1.1"));
        assertTrue(LanScan.isPrivateOrLocal("10.0.0.1"));
        assertTrue(LanScan.isPrivateOrLocal("172.16.5.4"));
        assertTrue(LanScan.isPrivateOrLocal("127.0.0.1"));
        assertTrue(LanScan.isPrivateOrLocal("169.254.10.2"));
        assertFalse(LanScan.isPrivateOrLocal("8.8.8.8"));
        assertFalse(LanScan.isPrivateOrLocal("172.32.0.1"));
    }

    // ------------------------------------------------------- probe policy

    @Test public void refuseIsAlive_openIsAlive_timeoutIsNot() {
        // .1 answers on 80 (open), .2 refuses everything (alive),
        // everyone else drops the probe (inconclusive).
        LanScan.Prober fake = (ip, port, timeoutMs) -> {
            if ("192.168.1.1".equals(ip))
                return port == 80 ? LanScan.Probe.OPEN : LanScan.Probe.TIMEOUT;
            if ("192.168.1.2".equals(ip))
                return LanScan.Probe.REFUSED;
            return LanScan.Probe.TIMEOUT;
        };

        LanScan.Result r = LanScan.scan("192.168.1.0/29",
                new int[]{80, 443}, 1, 4, fake);

        assertEquals("192.168.1.0/29", r.cidr);
        assertEquals(6, r.scanned);              // .1 .. .6
        assertEquals(6, r.hosts.size());
        assertEquals(2, r.aliveCount());

        LanScan.Host one = host(r, "192.168.1.1");
        assertTrue(one.alive);
        assertEquals("open", one.via);
        assertEquals(1, one.openPorts.size());
        assertEquals(Integer.valueOf(80), one.openPorts.get(0));

        LanScan.Host two = host(r, "192.168.1.2");
        assertTrue("ECONNREFUSED still proves the host is up", two.alive);
        assertEquals("refused", two.via);
        assertTrue(two.openPorts.isEmpty());

        LanScan.Host three = host(r, "192.168.1.3");
        assertFalse("a dropped probe proves nothing", three.alive);
        assertEquals("", three.via);
    }

    @Test public void scanningIsDeterministicAndIpSorted() {
        LanScan.Prober refuseAll = (ip, port, timeoutMs) -> LanScan.Probe.REFUSED;
        LanScan.Result a = LanScan.scan("192.168.0.0/29",
                new int[]{22}, 1, 2, refuseAll);
        LanScan.Result b = LanScan.scan("192.168.0.0/29",
                new int[]{22}, 1, 8, refuseAll);
        assertEquals(a.hosts.size(), b.hosts.size());
        for (int i = 0; i < a.hosts.size(); i++)
            assertEquals(a.hosts.get(i).ip, b.hosts.get(i).ip);
        assertEquals("192.168.0.1", a.hosts.get(0).ip);
        assertEquals("192.168.0.6", a.hosts.get(a.hosts.size() - 1).ip);
    }

    @Test public void proberThrowing_isInconclusive_notFatal() {
        LanScan.Prober broken = (ip, port, timeoutMs) -> {
            throw new RuntimeException("boom");
        };
        LanScan.Result r = LanScan.scan("192.168.0.0/30",
                new int[]{80}, 1, 2, broken);
        assertEquals(2, r.scanned);
        assertEquals(0, r.aliveCount());
    }

    private static LanScan.Host host(LanScan.Result r, String ip) {
        for (LanScan.Host h : r.hosts) if (h.ip.equals(ip)) return h;
        throw new AssertionError("host not in result: " + ip);
    }
}
