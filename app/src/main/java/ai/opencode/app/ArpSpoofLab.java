package ai.opencode.app;

import java.util.*;

 /**
  * Offline-only ARP anomaly simulator. It uses in-memory synthetic values only:
  * no sockets, packet creation/transmission, device ARP reads, or route changes.
  */
public final class ArpSpoofLab {
    private ArpSpoofLab() {}
    public enum AlertType { IP_TO_MAC_CHANGED, IP_CLAIMED_BY_MULTIPLE_MACS }

    public static final class Observation {
        public final String ip, mac;
        public Observation(String ip, String mac) {
            this.ip = normalizeIp(ip);
            this.mac = normalizeMac(mac);
        }
    }
    public static final class Alert {
        public final AlertType type;
        public final String ip, expectedMac, observedMac;
        Alert(AlertType type, String ip, String expectedMac, String observedMac) {
            this.type = type; this.ip = ip;
            this.expectedMac = expectedMac; this.observedMac = observedMac;
        }
    }
    public static final class Detector {
        private final Map<String,String> baseline = new LinkedHashMap<>();
        private final Map<String,Set<String>> seen = new LinkedHashMap<>();
        public Detector(Map<String,String> expectedBindings) {
            if (expectedBindings == null || expectedBindings.isEmpty())
                throw new IllegalArgumentException("At least one lab baseline binding is required");
            for (Map.Entry<String,String> e : expectedBindings.entrySet()) {
                String ip = normalizeIp(e.getKey()), mac = normalizeMac(e.getValue());
                baseline.put(ip, mac);
                Set<String> values = new LinkedHashSet<>(); values.add(mac); seen.put(ip, values);
            }
        }
        public List<Alert> observe(Observation observation) {
            if (observation == null) throw new IllegalArgumentException("observation is required");
            Set<String> addresses = seen.get(observation.ip);
            if (addresses == null) { addresses = new LinkedHashSet<>(); seen.put(observation.ip, addresses); }
            boolean added = addresses.add(observation.mac);
            List<Alert> alerts = new ArrayList<>();
            String expected = baseline.get(observation.ip);
            if (expected != null && !expected.equals(observation.mac))
                alerts.add(new Alert(AlertType.IP_TO_MAC_CHANGED, observation.ip, expected, observation.mac));
            if (added && addresses.size() > 1)
                alerts.add(new Alert(AlertType.IP_CLAIMED_BY_MULTIPLE_MACS, observation.ip, expected, observation.mac));
            return Collections.unmodifiableList(alerts);
        }
    }
    public enum Scenario { NORMAL, GATEWAY_MAC_CHANGE, DUPLICATE_IP_CLAIM }
    public static final class ScenarioResult {
        public final List<Observation> observations;
        public final List<Alert> alerts;
        ScenarioResult(List<Observation> o, List<Alert> a) {
            observations = Collections.unmodifiableList(new ArrayList<>(o));
            alerts = Collections.unmodifiableList(new ArrayList<>(a));
        }
    }
    public static ScenarioResult runScenario(Scenario scenario) {
        if (scenario == null) throw new IllegalArgumentException("scenario is required");
        Map<String,String> expected = new LinkedHashMap<>();
        expected.put("192.0.2.1", "02:00:00:00:00:01");
        expected.put("192.0.2.10", "02:00:00:00:00:10");
        Detector detector = new Detector(expected);
        List<Observation> observations = new ArrayList<>();
        List<Alert> alerts = new ArrayList<>();
        add(detector, observations, alerts, new Observation("192.0.2.1", "02:00:00:00:00:01"));
        add(detector, observations, alerts, new Observation("192.0.2.10", "02:00:00:00:00:10"));
        if (scenario == Scenario.GATEWAY_MAC_CHANGE)
            add(detector, observations, alerts, new Observation("192.0.2.1", "02:00:00:00:66:66"));
        if (scenario == Scenario.DUPLICATE_IP_CLAIM)
            add(detector, observations, alerts, new Observation("192.0.2.10", "02:00:00:00:66:66"));
        return new ScenarioResult(observations, alerts);
    }
    private static void add(Detector d, List<Observation> o, List<Alert> a, Observation v) {
        o.add(v); a.addAll(d.observe(v));
    }
    private static String normalizeIp(String value) {
        if (value == null || !value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
            throw new IllegalArgumentException("Invalid IPv4 address: " + value);
        String[] parts = value.split("\\.");
        StringBuilder out = new StringBuilder();
        for (int i=0;i<parts.length;i++) {
            int n = Integer.parseInt(parts[i]);
            if (n > 255) throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            if (i>0) out.append('.');
            out.append(n);
        }
        return out.toString();
    }
    private static String normalizeMac(String value) {
        if (value == null || !value.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}"))
            throw new IllegalArgumentException("Invalid MAC address: " + value);
        return value.toLowerCase(Locale.US);
    }
}
