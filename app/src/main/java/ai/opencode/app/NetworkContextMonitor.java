package ai.opencode.app;

/** Compares Android-exposed connection metadata without claiming ARP visibility. */
final class NetworkContextMonitor {
    static final class Snapshot {
        final String gateway;
        final String bssid;
        final boolean wifiTransport;

        Snapshot(String gateway, String bssid, boolean wifiTransport) {
            this.gateway = clean(gateway);
            this.bssid = clean(bssid);
            this.wifiTransport = wifiTransport;
        }

        private static String clean(String value) {
            return value == null || value.trim().isEmpty() ? null : value.trim();
        }

        boolean hasIdentity() {
            return gateway != null || bssid != null;
        }
    }

    private Snapshot baseline;
    private boolean firstObservation;

    void reset() {
        baseline = null;
        firstObservation = false;
    }

    boolean isFirstObservation() {
        return firstObservation;
    }

    String observe(Snapshot current) {
        firstObservation = false;
        if (current == null || !current.hasIdentity()) {
            return "No gateway or access-point identity is currently exposed by Android; monitoring continues without an identity baseline.";
        }
        if (baseline == null) {
            baseline = current;
            firstObservation = true;
            return "Baseline captured from Android connection metadata.";
        }

        StringBuilder changes = new StringBuilder();
        if (baseline.gateway != null && current.gateway != null
                && !baseline.gateway.equals(current.gateway)) {
            changes.append("gateway ").append(baseline.gateway).append(" -> ")
                    .append(current.gateway);
        }
        if (baseline.bssid != null && current.bssid != null
                && !baseline.bssid.equalsIgnoreCase(current.bssid)) {
            if (changes.length() > 0) changes.append("; ");
            changes.append("access-point BSSID ").append(baseline.bssid)
                    .append(" -> ").append(current.bssid);
        }
        baseline = new Snapshot(
                current.gateway != null ? current.gateway : baseline.gateway,
                current.bssid != null ? current.bssid : baseline.bssid,
                current.wifiTransport);
        return changes.length() == 0
                ? "No change in the Android-exposed gateway/AP identity."
                : "CHANGE · " + changes + ". Verify whether this was an expected network or roaming change.";
    }
}
