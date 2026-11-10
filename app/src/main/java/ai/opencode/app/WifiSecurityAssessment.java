package ai.opencode.app;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Pure-Java classification of Android Wi-Fi scan metadata; never probes or alters an AP. */
public final class WifiSecurityAssessment {
    private WifiSecurityAssessment() {}

    public enum Severity { INFO, LOW, MEDIUM, HIGH }

    public static final class AccessPoint {
        public final String ssid;
        public final String capabilities;
        public final int frequencyMhz;
        public final int signalDbm;

        public AccessPoint(String ssid, String capabilities, int frequencyMhz, int signalDbm) {
            this.ssid = ssid == null ? "" : ssid.trim();
            this.capabilities = capabilities == null ? "" : capabilities.toUpperCase(Locale.US);
            this.frequencyMhz = frequencyMhz;
            this.signalDbm = signalDbm;
        }
    }

    public static final class Finding {
        public final Severity severity;
        public final String ssid;
        public final String category;
        public final String detail;
        public final String recommendation;

        Finding(Severity severity, String ssid, String category,
                String detail, String recommendation) {
            this.severity = severity;
            this.ssid = ssid;
            this.category = category;
            this.detail = detail;
            this.recommendation = recommendation;
        }
    }

    public static List<Finding> assess(List<AccessPoint> accessPoints) {
        if (accessPoints == null || accessPoints.isEmpty()) return Collections.emptyList();
        List<Finding> findings = new ArrayList<>();
        for (AccessPoint ap : accessPoints) {
            if (ap == null) continue;
            String name = ap.ssid.isEmpty() ? "(hidden SSID)" : ap.ssid;
            String caps = ap.capabilities;
            if (caps.contains("WEP")) {
                findings.add(new Finding(Severity.HIGH, name, "WEP",
                        "WEP is obsolete and readily breakable.",
                        "Disable WEP and configure WPA2-AES or WPA3 with a strong unique passphrase."));
            } else if (caps.contains("WPA3") || caps.contains("SAE")) {
                findings.add(new Finding(Severity.INFO, name, "WPA3",
                        "WPA3/SAE security is advertised.",
                        "Keep router firmware current and use a strong unique passphrase."));
            } else if (caps.contains("WPA2")) {
                findings.add(new Finding(Severity.INFO, name, "WPA2",
                        "WPA2 security is advertised.",
                        "Prefer WPA3 where all clients support it; keep WPA2-AES and disable WPS."));
            } else if (caps.contains("OWE")) {
                findings.add(new Finding(Severity.LOW, name, "OWE",
                        "Enhanced Open encryption is advertised; it does not authenticate the network operator.",
                        "Verify the network identity before sharing sensitive information."));
            } else if (caps.contains("WPA")) {
                findings.add(new Finding(Severity.MEDIUM, name, "Legacy WPA",
                        "Legacy WPA is advertised without a WPA2/WPA3 marker.",
                        "Upgrade router security to WPA2-AES or WPA3."));
            } else if (caps.isEmpty() || caps.contains("[ESS]") || caps.contains("[IBSS]")) {
                findings.add(new Finding(Severity.HIGH, name, "Open network",
                        "No supported encryption marker is visible in this scan result.",
                        "Avoid sensitive activity or use a trusted encrypted connection; secure owned APs with WPA2/WPA3."));
            } else {
                findings.add(new Finding(Severity.LOW, name, "Unclassified security",
                        "The scan metadata does not identify a supported security mode: " + caps,
                        "Verify the access point configuration directly with its administrator."));
            }
        }
        return Collections.unmodifiableList(findings);
    }

    public static String bandForFrequency(int frequencyMhz) {
        if (frequencyMhz >= 5925 && frequencyMhz <= 7125) return "6 GHz";
        if (frequencyMhz >= 4900 && frequencyMhz < 5925) return "5 GHz";
        if (frequencyMhz >= 2400 && frequencyMhz < 2500) return "2.4 GHz";
        return "Unknown band";
    }

    public static String report(List<AccessPoint> accessPoints) {
        List<Finding> findings = assess(accessPoints);
        StringBuilder out = new StringBuilder("Android Wi-Fi passive security assessment\n");
        out.append("Scope: OS-provided scan metadata only; no association, probing, injection or packet transmission.\n");
        out.append("Access points observed: ").append(accessPoints == null ? 0 : accessPoints.size()).append('\n');
        for (Finding f : findings) {
            out.append(f.severity).append(" | ").append(f.ssid).append(" | ")
                    .append(f.category).append("\n  ").append(f.detail)
                    .append("\n  Recommendation: ").append(f.recommendation).append('\n');
        }
        if (findings.isEmpty()) out.append("No scan results available. No conclusion about network safety can be drawn.\n");
        out.append("Limitations: SSID/security metadata can be spoofed; one scan cannot prove AP identity, detect all rogue APs, or establish that a network is safe.\n");
        return out.toString();
    }
}
