package ai.opencode.app;

import android.content.Context;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Regression coverage for project-isolated OpenCode session storage. */
@RunWith(RobolectricTestRunner.class)
public class ContextRepairStoreTest {

    @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test public void repairTargetsTheActiveProjectsDatabase() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        File projectRoot = temporaryFolder.newFolder("active-project");
        String key = Binaries.projectStorageKey(projectRoot);
        File expected = new File(new File(new File(new File(
                context.getFilesDir(), "project-state"), key), "data"), "opencode");
        expected = new File(expected, "opencode.db");

        assertEquals(expected.getCanonicalFile(),
                storeDbFile(context, projectRoot).getCanonicalFile());
    }

    @Test public void repairRefusesToGuessWhenActiveProjectIsMissing() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        try {
            storeDbFile(context, null);
            fail("must not fall back to another project's database");
        } catch (InvocationTargetException expected) {
            assertTrue(expected.getCause() instanceof java.io.IOException);
        }
    }

    private static File storeDbFile(Context context, File projectRoot)
            throws Exception {
        Method method = RunHub.class.getDeclaredMethod(
                "storeDbFile", Context.class, File.class);
        method.setAccessible(true);
        return (File) method.invoke(null, context, projectRoot);
    }
}
