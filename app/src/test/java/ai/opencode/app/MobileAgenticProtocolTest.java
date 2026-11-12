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
    @Test public void wrapsNonEmptyMessageWithFivePhaseProtocol() {
        String wrapped = MobileAgenticProtocol.wrap("Inspect this project");
        assertTrue(wrapped.startsWith("<mobile-agentic-master version=\"2.0.0\">"));
        assertTrue(wrapped.contains("1 ANALYZE"));
        assertTrue(wrapped.contains("2 CLARIFY"));
        assertTrue(wrapped.contains("3 BLUEPRINT"));
        assertTrue(wrapped.contains("4 EXECUTE"));
        assertTrue(wrapped.contains("5 HANDOFF"));
        assertTrue(wrapped.contains("native question tool"));
        assertTrue(wrapped.contains("question.asked"));
        assertTrue(wrapped.contains("Approve and Revise"));
        assertTrue(wrapped.endsWith("Inspect this project"));
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

    @Test public void doesNotDoubleWrapAnAlreadyWrappedMessage() {
        String once = MobileAgenticProtocol.wrap("hello");
        assertEquals(once, MobileAgenticProtocol.wrap(once));
    }
}
