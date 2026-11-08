package ai.opencode.app;

import android.content.Context;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.io.File;
import java.io.FileOutputStream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class DebianBootstrapTest {
    @Test
    public void aptReady_requiresBothSuccessMarkerAndGuestGit() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        File debian = Debian.dir(context);
        File marker = new File(debian, ".apt-ready");
        File git = new File(Debian.rootfsDir(context), "usr/bin/git");
        File ca = new File(Debian.rootfsDir(context),
                "etc/ssl/certs/ca-certificates.crt");
        marker.getParentFile().mkdirs();
        git.getParentFile().mkdirs();
        marker.delete();
        git.delete();
        ca.delete();

        assertFalse(Debian.aptReady(context));

        try (FileOutputStream out = new FileOutputStream(marker)) {
            out.write("verified\n".getBytes("UTF-8"));
        }
        assertFalse(Debian.aptReady(context));

        try (FileOutputStream out = new FileOutputStream(git)) {
            out.write(new byte[] {1});
        }
        assertFalse(Debian.aptReady(context));
        ca.getParentFile().mkdirs();
        try (FileOutputStream out = new FileOutputStream(ca)) {
            out.write(new byte[] {1});
        }
        assertTrue(Debian.aptReady(context));
    }

    @Test
    public void aptRecovery_restoresDebconfBeforeConfiguringPendingPackages() {
        String command = Debian.aptRecoveryCommand();
        int update = command.indexOf("apt-get update");
        int debconf = command.indexOf("apt-get install -y --no-install-recommends debconf");
        int frontendCheck = command.indexOf("test -x /usr/share/debconf/frontend");
        int configure = command.indexOf("dpkg --configure -a");
        int appPackages = command.indexOf("apt-get install -y --no-install-recommends git ca-certificates");
        int audit = command.indexOf("dpkg --audit");

        assertTrue(update >= 0);
        assertTrue(debconf > update);
        assertTrue(frontendCheck > debconf);
        assertTrue(configure > frontendCheck);
        assertTrue(appPackages > configure);
        assertTrue(audit > appPackages);
    }

    @Test
    public void aptRecovery_requiresBothDebconfExecutablesBeforeDpkgRecovery() {
        String command = Debian.aptRecoveryCommand();
        assertTrue(command.contains("[ ! -x /usr/sbin/dpkg-preconfigure ]"));
        assertTrue(command.contains("[ ! -x /usr/share/debconf/frontend ]"));
        assertTrue(command.contains("test -x /usr/sbin/dpkg-preconfigure"));
        assertTrue(command.contains("test -x /usr/share/debconf/frontend"));
        assertTrue(command.contains("test -z \"$(dpkg --audit)\""));
    }

}
