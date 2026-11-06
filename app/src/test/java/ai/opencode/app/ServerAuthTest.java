package ai.opencode.app;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import static org.junit.Assert.*;

public class ServerAuthTest {
    @Test public void passwordIsStableAndNonempty() {
        assertEquals(ServerAuth.password(), ServerAuth.password());
        assertTrue(ServerAuth.password().length() >= 40);
    }

    @Test public void headerMatchesServerCredential() {
        String h = ServerAuth.authorizationHeader();
        assertTrue(h.startsWith("Basic "));
        String decoded = new String(Base64.getDecoder().decode(h.substring(6)),
                StandardCharsets.UTF_8);
        assertEquals("opencode:" + ServerAuth.password(), decoded);
    }

    @Test public void childReceivesSameCredential() {
        ProcessBuilder pb = new ProcessBuilder("true");
        ServerAuth.configureServer(pb);
        assertEquals("opencode", pb.environment().get("OPENCODE_SERVER_USERNAME"));
        assertEquals(ServerAuth.password(),
                pb.environment().get("OPENCODE_SERVER_PASSWORD"));
    }
}
