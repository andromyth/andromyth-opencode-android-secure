package ai.opencode.app;

import android.content.Context;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MobileAgenticProtocolTest {
    @Test public void userMessageIsNotPrefixedWithProtocol() {
        String message = "Inspect this project";
        assertEquals(message, MobileAgenticProtocol.wrap(message));
        assertFalse(MobileAgenticProtocol.wrap(message)
                .startsWith("<mobile-agentic-master"));
    }

    @Test public void emptyAndNullMessagesRemainUnchanged() {
        assertNull(MobileAgenticProtocol.wrap(null));
        assertEquals("  ", MobileAgenticProtocol.wrap("  "));
    }

    @Test public void installsGlobalSkillOnceAndPreservesUserEdits() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        File target = Binaries.mobileAgenticSkillFile(context);
        if (target.exists()) target.delete();
        Binaries.installMobileAgenticSkill(context);
        assertTrue(target.isFile());
        String bundled = new String(Files.readAllBytes(target.toPath()),
                StandardCharsets.UTF_8);
        assertTrue(bundled.contains("# Mobile Agentic Master v2.0"));

        Files.write(target.toPath(), "user-customized".getBytes(StandardCharsets.UTF_8));
        Binaries.installMobileAgenticSkill(context);
        assertEquals("user-customized", new String(Files.readAllBytes(target.toPath()),
                StandardCharsets.UTF_8));
    }

    @Test public void alreadyAuthoredProtocolTextIsNotModified() {
        String message = "<mobile-agentic-master version=\"2.0.0\">\\nmanual text";
        assertEquals(message, MobileAgenticProtocol.wrap(message));
    }
}
