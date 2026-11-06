#!/usr/bin/env python3
from pathlib import Path

ROOT = Path.cwd()

def replace_once(path, old, new):
    p = ROOT / path
    s = p.read_text(encoding="utf-8")
    count = s.count(old)
    if count != 1:
        raise SystemExit(f"Refusing to patch {path}: expected one exact match, found {count}")
    p.write_text(s.replace(old, new, 1), encoding="utf-8")
    print("patched", path)

auth = ROOT / "app/src/main/java/ai/opencode/app/ServerAuth.java"
if auth.exists():
    raise SystemExit("ServerAuth.java already exists; refusing to overwrite")
auth.write_text("""package ai.opencode.app;

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
""", encoding="utf-8")

replace_once(
    "app/src/main/java/ai/opencode/app/Api.java",
    "        c.setUseCaches(false);\n",
    "        c.setUseCaches(false);\n        c.setRequestProperty(\"Authorization\", ServerAuth.authorizationHeader());\n",
)
replace_once(
    "app/src/main/java/ai/opencode/app/ServerService.java",
    '            appendDiag("env", "applyEnv failed: " + t);\n        }\n\n        long[] deaths = new long[8];        // recent death timestamps (ring)',
    '            appendDiag("env", "applyEnv failed: " + t);\n        }\n        // Protect the app-private HTTP API with a per-process random password.\n        ServerAuth.configureServer(pb);\n\n        long[] deaths = new long[8];        // recent death timestamps (ring)',
)
replace_once(
    "app/build.gradle",
    """// P6: persistent debug keystore (signature continuity across sandbox wipes).
// Falls back to the default ~/.android/debug.keystore when absent (e.g. a
// fresh clone from GitHub), so building from source never breaks.
// Prefer an in-repo keystore (committed so CI and every machine sign with the
// SAME key and updates install in place); fall back to the historical sibling
// path, then to the android default debug keystore.
def persistentDebugKeystore = new File(rootDir, 'keystore/debug.keystore')
if (!persistentDebugKeystore.exists()) {
    persistentDebugKeystore = new File(rootDir, '../keystore/debug.keystore')
}
""",
    """// Never use a signing key committed to source control.
def ciStore = System.getenv('OPENCODE_SIGNING_KEYSTORE')
def ciStorePassword = System.getenv('OPENCODE_SIGNING_STORE_PASSWORD')
def ciAlias = System.getenv('OPENCODE_SIGNING_KEY_ALIAS')
def ciKeyPassword = System.getenv('OPENCODE_SIGNING_KEY_PASSWORD')
def ciSigningReady = ciStore && ciStorePassword && ciAlias && ciKeyPassword
""",
)
replace_once(
    "app/build.gradle",
    """    signingConfigs {
        debug {
            if (persistentDebugKeystore.exists()) {
                storeFile persistentDebugKeystore
                storePassword 'android'
                keyAlias 'androiddebugkey'
                keyPassword 'android'
            }
        }
    }

    buildTypes {
        release { minifyEnabled false }
    }
""",
    """    signingConfigs {
        if (ciSigningReady) {
            hardened {
                storeFile file(ciStore)
                storePassword ciStorePassword
                keyAlias ciAlias
                keyPassword ciKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            if (ciSigningReady) signingConfig signingConfigs.hardened
        }
        release {
            minifyEnabled false
            if (ciSigningReady) signingConfig signingConfigs.hardened
        }
    }
""",
)
gitignore = ROOT / ".gitignore"
ignored = gitignore.read_text(encoding="utf-8")
if "!keystore/debug.keystore\n" not in ignored:
    raise SystemExit("Expected tracked debug-keystore exception not found")
gitignore.write_text(ignored.replace("!keystore/debug.keystore\n", ""), encoding="utf-8")
key = ROOT / "keystore/debug.keystore"
if not key.is_file():
    raise SystemExit("Expected committed keystore missing; refusing partial hardening")
key.unlink()
print("removed committed debug keystore")

test = ROOT / "app/src/test/java/ai/opencode/app/ServerAuthTest.java"
if test.exists():
    raise SystemExit("ServerAuthTest.java already exists; refusing to overwrite")
test.parent.mkdir(parents=True, exist_ok=True)
test.write_text("""package ai.opencode.app;

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
""", encoding="utf-8")
print("security hardening source changes applied")
