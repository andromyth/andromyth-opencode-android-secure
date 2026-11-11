package ai.opencode.app;

import static org.junit.Assert.*;
import org.junit.Test;

public class NetworkContextMonitorTest {
    @Test public void capturesBaselineAndReportsStableContext() {
        NetworkContextMonitor monitor = new NetworkContextMonitor();
        NetworkContextMonitor.Snapshot snapshot =
                new NetworkContextMonitor.Snapshot("192.168.1.1", "aa:bb:cc:dd:ee:ff", true);
        assertTrue(monitor.observe(snapshot).contains("Baseline"));
        assertTrue(monitor.isFirstObservation());
        assertTrue(monitor.observe(snapshot).contains("No change"));
        assertFalse(monitor.isFirstObservation());
    }

    @Test public void reportsGatewayAndBssidChangesAsContextWarnings() {
        NetworkContextMonitor monitor = new NetworkContextMonitor();
        monitor.observe(new NetworkContextMonitor.Snapshot(
                "192.168.1.1", "aa:bb:cc:dd:ee:ff", true));
        String result = monitor.observe(new NetworkContextMonitor.Snapshot(
                "192.168.1.254", "11:22:33:44:55:66", true));
        assertTrue(result.startsWith("CHANGE"));
        assertTrue(result.contains("192.168.1.254"));
        assertTrue(result.contains("11:22:33:44:55:66"));
    }

    @Test public void redactedOrMissingMetadataDoesNotCreateFalseChange() {
        NetworkContextMonitor monitor = new NetworkContextMonitor();
        monitor.observe(new NetworkContextMonitor.Snapshot("192.168.1.1", null, true));
        assertTrue(monitor.observe(new NetworkContextMonitor.Snapshot(null, null, true))
                .contains("No gateway or access-point identity"));
        assertTrue(monitor.observe(new NetworkContextMonitor.Snapshot("192.168.1.1", null, true))
                .contains("No change"));
    }

    @Test public void resetStartsANewBaseline() {
        NetworkContextMonitor monitor = new NetworkContextMonitor();
        monitor.observe(new NetworkContextMonitor.Snapshot("192.168.1.1", null, true));
        monitor.reset();
        assertTrue(monitor.observe(new NetworkContextMonitor.Snapshot("192.168.2.1", null, true))
                .contains("Baseline"));
    }
}
