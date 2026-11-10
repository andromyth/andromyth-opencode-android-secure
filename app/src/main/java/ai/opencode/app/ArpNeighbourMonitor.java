package ai.opencode.app;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only parser for the kernel neighbour cache exposed as /proc/net/arp. */
public final class ArpNeighbourMonitor {
    private ArpNeighbourMonitor() {}
    public static Map<String,String> readSnapshot() throws IOException {
        Map<String,String> rows = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (header) { header = false; continue; }
                String[] f = line.trim().split("\\s+");
                if (f.length < 6) continue;
                try {
                    if ((Integer.parseInt(f[2], 16) & 0x2) == 0) continue;
                    ArpSpoofLab.Observation o = new ArpSpoofLab.Observation(f[0], f[3]);
                    rows.put(o.ip, o.mac);
                } catch (IllegalArgumentException ignored) { }
            }
        }
        return rows;
    }
}
