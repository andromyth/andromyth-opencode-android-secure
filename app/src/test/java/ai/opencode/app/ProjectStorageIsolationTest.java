package ai.opencode.app;

import org.junit.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/** Pins the per-project OpenCode storage namespace. */
public class ProjectStorageIsolationTest {

    @Test public void sameCanonicalProjectGetsStableNamespace() throws Exception {
        File project = Files.createTempDirectory("oc-project-a").toFile();
        File alias = new File(project, ".");
        assertEquals(Binaries.projectStorageKey(project),
                Binaries.projectStorageKey(alias));
    }

    @Test public void differentProjectsNeverShareNamespace() throws Exception {
        File first = Files.createTempDirectory("oc-project-a").toFile();
        File second = Files.createTempDirectory("oc-project-b").toFile();
        assertNotEquals(Binaries.projectStorageKey(first),
                Binaries.projectStorageKey(second));
    }
}
