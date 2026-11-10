package ai.opencode.app;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only adapter for Android/Linux's IPv4 ARP neighbour cache. */
public final class ArpNeighbourMonitor {
    private ArpNeighbourMonitor() {}

    /** Reads the kernel table; Android/OEM policy may deny this path. */
    public static Map<String,String> readSnapshot() throws IOException {
        try (Reader reader = new FileReader("/proc/net/arp")) {
            return parse(reader);
        }
    }

    /** Parser kept separate from filesystem access so it can be tested on every Android build. */
    static Map<String,String> parse(Reader source) throws IOException {
        Map<String,String> rows = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(source)) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (header) { header = false; continue; }
                if (line.trim().isEmpty()) continue;
                String[] fields = line.trim().split("\\s+");
                if (fields.length < 6) continue;
                try {
                    int flags = Integer.parseInt(fields[2].replaceFirst("^0x", ""), 16);
                    if ((flags & 0x2) == 0) continue; // Ignore incomplete entries.
                    ArpSpoofLab.Observation observation =
                            new ArpSpoofLab.Observation(fields[0], fields[3]);
                    rows.put(observation.ip, observation.mac);
                } catch (IllegalArgumentException ignored) {
                    // Ignore malformed rows; do not let one bad row invalidate the snapshot.
                }
            }
        }
        return Collections.unmodifiableMap(rows);
    }
}
