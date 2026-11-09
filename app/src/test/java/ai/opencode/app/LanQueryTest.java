package ai.opencode.app;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * P61 — query-string parsing for the enriched /lan endpoint: port ranges,
 * presets and flags, pinned without any network access.
 */
public class LanQueryTest {

    @Test public void parsesListsAndRanges() {
        int[] p = LanQuery.parsePorts("22, 80, 8000-8005");
        assertEquals(8, p.length);
        assertEquals(22, p[0]);
        assertEquals(80, p[1]);
        assertEquals(8000, p[2]);
        assertEquals(8005, p[7]);
    }

    @Test public void deduplicatesAndSorts() {
        assertArrayEquals(new int[]{22, 80, 443},
                LanQuery.parsePorts("443,80,443,22"));
    }

    @Test public void invalidTokensAreIgnored() {
        assertArrayEquals(new int[]{22},
                LanQuery.parsePorts("0,-5,70000,abc,22"));
    }

    @Test public void blankFallsBackToDefault() {
        assertArrayEquals(LanScan.DEFAULT_PORTS, LanQuery.parsePorts("   "));
        assertArrayEquals(LanScan.DEFAULT_PORTS, LanQuery.parsePorts(null));
    }

    @Test public void rangesAreCapped() {
        int[] p = LanQuery.parsePorts("1-5000");
        assertEquals(LanQuery.MAX_PORTS, p.length);
        assertEquals(1, p[0]);
        assertEquals(LanQuery.MAX_PORTS, p[p.length - 1]);
    }

    @Test public void profilesExist() {
        assertNotNull(LanQuery.profile("common"));
        assertTrue(contains(LanQuery.profile("common"), 53));
        assertTrue(contains(LanQuery.profile("common"), 445));
        assertNotNull(LanQuery.profile("MEDIA"));
        assertTrue(contains(LanQuery.profile("iot"), 1883));
        assertNull(LanQuery.profile("nope"));
    }

    @Test public void booleansAndInts() {
        assertTrue(LanQuery.parseBool("YES", false));
        assertTrue(LanQuery.parseBool("1", false));
        assertFalse(LanQuery.parseBool("0", true));
        assertFalse(LanQuery.parseBool("off", true));
        assertTrue(LanQuery.parseBool("garbage", true));
        assertEquals(7, LanQuery.parsePositiveInt("7", 3));
        assertEquals(3, LanQuery.parsePositiveInt("-1", 3));
        assertEquals(3, LanQuery.parsePositiveInt("x", 3));
        assertEquals(3, LanQuery.parsePositiveInt(null, 3));
    }

    private static boolean contains(int[] a, int v) {
        if (a == null) return false;
        for (int x : a) if (x == v) return true;
        return false;
    }
}
