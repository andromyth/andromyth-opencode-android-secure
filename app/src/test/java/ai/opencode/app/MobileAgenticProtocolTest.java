package ai.opencode.app;

import org.junit.Test;
import static org.junit.Assert.*;

public class MobileAgenticProtocolTest {
    @Test public void wrapsNonEmptyMessageWithFivePhaseProtocol() {
        String wrapped = MobileAgenticProtocol.wrap("Inspect this project");
        assertTrue(wrapped.startsWith("<mobile-agentic-master version=\"2.0.0\">"));
        assertTrue(wrapped.contains("1 ANALYZE"));
        assertTrue(wrapped.contains("2 CLARIFY"));
        assertTrue(wrapped.contains("3 BLUEPRINT"));
        assertTrue(wrapped.contains("4 EXECUTE"));
        assertTrue(wrapped.contains("5 HANDOFF"));
        assertTrue(wrapped.endsWith("Inspect this project"));
    }

    @Test public void emptyAndNullMessagesRemainUnchanged() {
        assertNull(MobileAgenticProtocol.wrap(null));
        assertEquals("  ", MobileAgenticProtocol.wrap("  "));
    }

    @Test public void doesNotDoubleWrapAnAlreadyWrappedMessage() {
        String once = MobileAgenticProtocol.wrap("hello");
        assertEquals(once, MobileAgenticProtocol.wrap(once));
    }
}
