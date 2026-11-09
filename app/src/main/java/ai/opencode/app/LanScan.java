package ai.opencode.app;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Non-root LAN host discovery.
 *
 * Android apps (and a non-root Termux, and this app's proot guest) cannot
 * create raw sockets, so ARP scans, SYN scans and packet capture are out of
 * reach: CAP_NET_RAW / CAP_NET_ADMIN are not granted (see
 * scripts/capability-check.sh). What IS available is an ordinary TCP
 * connect(). A completed handshake proves the host is up AND names an open
 * port; an ECONNREFUSED proves the host is up with that port closed; a
 * timeout proves nothing (the host may simply drop probes). That is enough
 * to find the devices on a home/office LAN without any privilege.
 *
 * Pure Java on purpose — no Android imports — so the CIDR math and the
 * probe policy are unit-testable on the JVM (LanScanTest).
 */
public final class LanScan {

    /** Ports worth trying on a typical LAN host. Kept small: every host
     *  costs one connect per port, and the whole scan is bounded by
     *  MAX_HOSTS below. */
    public static final int[] DEFAULT_PORTS = {22, 80, 443, 445, 3389, 8080};

    /** Per-connect timeout. A dropped SYN costs this long, so keep it short. */
    public static final int DEFAULT_TIMEOUT_MS = 200;

    /** Hosts probed concurrently. */
    public static final int DEFAULT_THREADS = 64;

    /** Hard cap on hosts per scan. A /16 has 65k addresses; scanning all of
     *  them from a phone would take minutes and hammer the LAN, so a wide
     *  prefix is narrowed to the /24 that contains our own address. */
    public static final int MAX_HOSTS = 254;

    private LanScan() {}

    /** What one connect() attempt told us. */
    public enum Probe {
        /** Handshake completed — host up, port open. */
        OPEN,
        /** ECONNREFUSED — host up, port closed. Still proves liveness. */
        REFUSED,
        /** No answer within the timeout — inconclusive. */
        TIMEOUT,
        /** Anything else (unreachable, local error) — inconclusive. */
        ERROR
    }

    /** Injected so tests can be deterministic and never touch a network. */
    public interface Prober {
        Probe probe(String ip, int port, int timeoutMs);
    }

    /** One candidate host and what the scan learned about it. */
    public static final class Host {
        public final String ip;
        public final boolean alive;
        public final List<Integer> openPorts;   // ascending
        public final String via;                // "open" | "refused" | ""

        Host(String ip, boolean alive, List<Integer> openPorts, String via) {
            this.ip = ip;
            this.alive = alive;
            this.openPorts = Collections.unmodifiableList(openPorts);
            this.via = via;
        }
    }

    /** The result of scanning one CIDR. */
    public static final class Result {
        public final String cidr;
        public final int scanned;
        public final List<Host> hosts;          // ascending by IP
        public final long durationMs;

        Result(String cidr, int scanned, List<Host> hosts, long durationMs) {
            this.cidr = cidr;
            this.scanned = scanned;
            this.hosts = Collections.unmodifiableList(hosts);
            this.durationMs = durationMs;
        }

        public int aliveCount() {
            int n = 0;
            for (Host h : hosts) if (h.alive) n++;
            return n;
        }
    }

    /** The real prober: an ordinary TCP connect, no privilege required. */
    public static Prober socketProber() {
        return (ip, port, timeoutMs) -> {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(InetAddress.getByName(ip), port),
                        timeoutMs);
                return Probe.OPEN;
            } catch (SocketTimeoutException e) {
                return Probe.TIMEOUT;
            } catch (ConnectException e) {
                // ECONNREFUSED: the packet reached a live host and was
                // rejected. Treat as alive even though the port is closed.
                return Probe.REFUSED;
            } catch (Exception e) {
                return Probe.ERROR;
            } finally {
                try { s.close(); } catch (IOException ignored) {}
            }
        };
    }

    /**
     * Scan one IPv4 CIDR. Never throws: a bad CIDR or a prober failure
     * yields an empty/inconclusive result.
     */
    public static Result scan(String cidr, int[] ports, int timeoutMs,
                              int threads, Prober prober) {
        long t0 = System.currentTimeMillis();
        List<String> candidates = candidateHosts(cidr);
        String normalized = normalizeCidr(cidr);
        int[] usePorts = (ports == null || ports.length == 0)
                ? DEFAULT_PORTS : ports;
        int useTimeout = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
        int useThreads = threads > 0 ? threads : DEFAULT_THREADS;
        Prober p = prober != null ? prober : socketProber();

        List<Host> out = new ArrayList<>(candidates.size());
        if (candidates.isEmpty()) {
            return new Result(normalized, 0, out,
                    System.currentTimeMillis() - t0);
        }

        ExecutorService pool = Executors.newFixedThreadPool(
                Math.min(useThreads, Math.max(1, candidates.size())));
        List<Future<Host>> futures = new ArrayList<>(candidates.size());
        try {
            for (String ip : candidates) {
                final String target = ip;
                futures.add(pool.submit(new Callable<Host>() {
                    @Override public Host call() {
                        return scanHost(target, usePorts, useTimeout, p);
                    }
                }));
            }
            for (Future<Host> f : futures) {
                try {
                    out.add(f.get());
                } catch (Exception e) {
                    // A task that blew up contributes nothing; keep going.
                }
            }
        } finally {
            pool.shutdownNow();
            try { pool.awaitTermination(2, TimeUnit.SECONDS); }
            catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }
        Collections.sort(out, (a, b) -> Long.compare(ipToLong(a.ip), ipToLong(b.ip)));
        return new Result(normalized, candidates.size(), out,
                System.currentTimeMillis() - t0);
    }

    private static Host scanHost(String ip, int[] ports, int timeoutMs, Prober p) {
        List<Integer> open = new ArrayList<>();
        boolean alive = false;
        String via = "";
        for (int port : ports) {
            Probe r;
            try {
                r = p.probe(ip, port, timeoutMs);
            } catch (Exception e) {
                r = Probe.ERROR;
            }
            if (r == Probe.OPEN) {
                open.add(port);
                alive = true;
                if (via.isEmpty()) via = "open";
            } else if (r == Probe.REFUSED) {
                alive = true;
                if (via.isEmpty()) via = "refused";
            }
        }
        Collections.sort(open);
        return new Host(ip, alive, open, via);
    }

    // ------------------------------------------------------------ CIDR math

    /** Parse "a.b.c.d/prefix" into the usable host addresses. A prefix
     *  wider than MAX_HOSTS (i.e. fewer than 8 bits of host space) is
     *  narrowed to the /24 containing the given address. Returns an empty
     *  list for malformed input. */
    public static List<String> candidateHosts(String cidr) {
        List<String> out = new ArrayList<>();
        if (cidr == null) return out;
        String s = cidr.trim();
        int slash = s.indexOf('/');
        if (slash <= 0 || slash == s.length() - 1) return out;
        String ipPart = s.substring(0, slash);
        int prefix;
        try {
            prefix = Integer.parseInt(s.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return out;
        }
        long ip = ipToLong(ipPart);
        if (ip < 0) return out;
        if (prefix < 0 || prefix > 32) return out;

        // /32 is a single address; /31 is a two-host point-to-point link.
        if (prefix >= 31) {
            long count = 1L << (32 - prefix);
            for (long i = 0; i < count; i++) out.add(longToIp(ip + i));
            return out;
        }

        long mask = maskFor(prefix);
        long network = ip & mask;
        long total = 1L << (32 - prefix);       // includes network+broadcast
        long usable = total - 2;

        if (usable > MAX_HOSTS) {
            // Narrow to the /24 that contains our own address.
            long net24 = ip & 0xFFFFFF00L;
            for (long i = 1; i <= 254; i++) out.add(longToIp(net24 + i));
            return out;
        }
        for (long i = 1; i <= usable; i++) out.add(longToIp(network + i));
        return out;
    }

    /** Canonical "network/prefix" form, or the input when it cannot be
     *  parsed. Used in the JSON so hosts always line up with a subnet. */
    public static String normalizeCidr(String cidr) {
        if (cidr == null) return "";
        String s = cidr.trim();
        int slash = s.indexOf('/');
        if (slash <= 0 || slash == s.length() - 1) return s;
        long ip = ipToLong(s.substring(0, slash));
        int prefix;
        try {
            prefix = Integer.parseInt(s.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return s;
        }
        if (ip < 0 || prefix < 0 || prefix > 32) return s;
        return longToIp(ip & maskFor(prefix)) + "/" + prefix;
    }

    /** The prefix length that would cover two IPv4 addresses, or -1. */
    public static int commonPrefix(String a, String b) {
        long x = ipToLong(a);
        long y = ipToLong(b);
        if (x < 0 || y < 0) return -1;
        long diff = x ^ y;
        if (diff == 0) return 32;
        int bits = 0;
        while (diff > 0) { bits++; diff >>>= 1; }
        return 32 - bits;
    }

    /** Unsigned 32-bit value as a long, or -1 for malformed input. */
    public static long ipToLong(String ip) {
        if (ip == null) return -1;
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) return -1;
        long v = 0;
        for (String part : parts) {
            if (part.isEmpty()) return -1;
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return -1;
            }
            if (octet < 0 || octet > 255) return -1;
            v = (v << 8) | octet;
        }
        return v & 0xFFFFFFFFL;
    }

    /** Inverse of {@link #ipToLong}. */
    public static String longToIp(long v) {
        return ((v >>> 24) & 0xFF) + "." + ((v >>> 16) & 0xFF) + "."
                + ((v >>> 8) & 0xFF) + "." + (v & 0xFF);
    }

    private static long maskFor(int prefix) {
        return prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    }

    /** True for RFC1918 / link-local / loopback IPv4. Used to keep the
     *  scan on networks that actually host devices. */
    public static boolean isPrivateOrLocal(String ip) {
        long v = ipToLong(ip);
        if (v < 0) return false;
        if ((v & 0xFF000000L) == 0x7F000000L) return true;   // 127/8
        if ((v & 0xFFFF0000L) == 0xA9FE0000L) return true;  // 169.254/16
        if ((v & 0xFF000000L) == 0x0A000000L) return true;   // 10/8
        if ((v & 0xFFF00000L) == 0xAC100000L) return true;   // 172.16/12
        if ((v & 0xFFFF0000L) == 0xC0A80000L) return true;   // 192.168/16
        return false;
    }
}
