package ai.opencode.app;

import static org.junit.Assert.*;
import java.io.StringReader;
import java.util.Map;
import org.junit.Test;

public class ArpNeighbourMonitorTest {
    @Test public void parsesCompleteRowsAndNormalizesMac() throws Exception {
        String input = "IP address HW type Flags HW address Mask Device\\n"
                + "192.168.1.1 0x1 0x2 AA:BB:CC:DD:EE:FF * wlan0\\n"
                + "192.168.1.2 0x1 0x0 00:00:00:00:00:00 * wlan0\\n";
        Map<String,String> rows = ArpNeighbourMonitor.parse(new StringReader(input));
        assertEquals(1, rows.size());
        assertEquals("aa:bb:cc:dd:ee:ff", rows.get("192.168.1.1"));
        assertFalse(rows.containsKey("192.168.1.2"));
    }

    @Test public void ignoresMalformedRowsAndKeepsValidEntries() throws Exception {
        String input = "IP address HW type Flags HW address Mask Device\\n"
                + "bad-ip 0x1 0x2 aa:bb:cc:dd:ee:ff * wlan0\\n"
                + "192.168.1.2 0x1 0x2 malformed * wlan0\\n"
                + "192.168.1.3 0x1 0x2 02:00:00:00:00:03 * wlan0\\n";
        Map<String,String> rows = ArpNeighbourMonitor.parse(new StringReader(input));
        assertEquals(1, rows.size());
        assertEquals("02:00:00:00:00:03", rows.get("192.168.1.3"));
    }

    @Test public void emptyAndIncompleteTablesReturnEmptySnapshot() throws Exception {
        assertTrue(ArpNeighbourMonitor.parse(new StringReader(
                "IP address HW type Flags HW address Mask Device\\n"
                + "192.168.1.2 0x1 0x0 00:00:00:00:00:00 * wlan0\\n")).isEmpty());
        assertTrue(ArpNeighbourMonitor.parse(new StringReader("")).isEmpty());
    }
}
