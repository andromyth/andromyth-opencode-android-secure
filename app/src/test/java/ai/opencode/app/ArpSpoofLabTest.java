package ai.opencode.app;

import org.junit.Test;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import static org.junit.Assert.*;

public class ArpSpoofLabTest {
    @Test public void normalScenarioHasNoAlerts() {
        ArpSpoofLab.ScenarioResult r = ArpSpoofLab.runScenario(ArpSpoofLab.Scenario.NORMAL);
        assertEquals(2, r.observations.size());
        assertTrue(r.alerts.isEmpty());
    }
    @Test public void changedGatewayMacIsDetected() {
        ArpSpoofLab.ScenarioResult r = ArpSpoofLab.runScenario(ArpSpoofLab.Scenario.GATEWAY_MAC_CHANGE);
        assertEquals(2, r.alerts.size());
        assertEquals(ArpSpoofLab.AlertType.IP_TO_MAC_CHANGED, r.alerts.get(0).type);
        assertEquals(ArpSpoofLab.AlertType.IP_CLAIMED_BY_MULTIPLE_MACS, r.alerts.get(1).type);
        assertEquals("192.0.2.1", r.alerts.get(0).ip);
    }
    @Test public void duplicateIpClaimIsDetected() {
        ArpSpoofLab.ScenarioResult r = ArpSpoofLab.runScenario(ArpSpoofLab.Scenario.DUPLICATE_IP_CLAIM);
        assertEquals(2, r.alerts.size());
        assertEquals("192.0.2.10", r.alerts.get(0).ip);
    }
    @Test public void repeatedSameBindingDoesNotAlert() {
        Map<String,String> baseline = new LinkedHashMap<>();
        baseline.put("192.0.2.1", "02:00:00:00:00:01");
        ArpSpoofLab.Detector d = new ArpSpoofLab.Detector(baseline);
        ArpSpoofLab.Observation o = new ArpSpoofLab.Observation("192.0.2.1", "02:00:00:00:00:01");
        assertTrue(d.observe(o).isEmpty());
        assertTrue(d.observe(o).isEmpty());
    }
    @Test public void repeatedChangedBindingIsReportedOnlyOnce() {
        Map<String,String> baseline = new LinkedHashMap<>();
        baseline.put("192.0.2.1", "02:00:00:00:00:01");
        ArpSpoofLab.Detector detector = new ArpSpoofLab.Detector(baseline);
        ArpSpoofLab.Observation changed =
                new ArpSpoofLab.Observation("192.0.2.1", "02:00:00:00:66:66");
        assertEquals(2, detector.observe(changed).size());
        assertTrue(detector.observe(changed).isEmpty());
    }
    @Test public void secondDistinctMacChangeIsReportedOnce() {
        Map<String,String> baseline = new LinkedHashMap<>();
        baseline.put("192.0.2.1", "02:00:00:00:00:01");
        ArpSpoofLab.Detector detector = new ArpSpoofLab.Detector(baseline);
        detector.observe(new ArpSpoofLab.Observation("192.0.2.1", "02:00:00:00:66:66"));
        assertEquals(2, detector.observe(
                new ArpSpoofLab.Observation("192.0.2.1", "02:00:00:00:77:77")).size());
    }
    @Test public void invalidIpAndMacAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new ArpSpoofLab.Observation("192.0.2.999", "02:00:00:00:00:01"));
        assertThrows(IllegalArgumentException.class, () -> new ArpSpoofLab.Observation("192.0.2.1", "not-a-mac"));
    }
    @Test public void detectorRequiresBaseline() {
        assertThrows(IllegalArgumentException.class, () -> new ArpSpoofLab.Detector(Collections.<String,String>emptyMap()));
    }
}
