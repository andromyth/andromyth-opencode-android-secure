package ai.opencode.app;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/** Per-process HTTP Basic authentication for the app-private loopback server. */
public final class ServerAuth {
    private static final String USERNAME = "opencode";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static volatile String password;
    private ServerAuth() {}

    static String password() {
        String value = password;
        if (value != null) return value;
        synchronized (ServerAuth.class) {
            if (password == null) {
                byte[] secret = new byte[32];
                RANDOM.nextBytes(secret);
                password = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
            }
            return password;
        }
    }

    static String authorizationHeader() {
        String pair = USERNAME + ":" + password();
        return "Basic " + Base64.getEncoder().encodeToString(
                pair.getBytes(StandardCharsets.UTF_8));
    }

    static void configureServer(ProcessBuilder builder) {
        Map<String, String> env = builder.environment();
        env.put("OPENCODE_SERVER_USERNAME", USERNAME);
        env.put("OPENCODE_SERVER_PASSWORD", password());
    }
}
