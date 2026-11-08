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
    public void aptRecovery_extractsDebconfPackageBeforeDpkgConfiguration() {
        String command = Debian.aptRecoveryCommand();
        int update = command.indexOf("apt-get update");
        int download = command.indexOf("apt-get download debconf");
        int extract = command.indexOf("dpkg-deb -x");
        int preconfigure = command.indexOf("test -x /usr/sbin/dpkg-preconfigure");
        int frontend = command.indexOf("test -x /usr/share/debconf/frontend");
        int configure = command.indexOf("dpkg --configure -a");
        int appPackages = command.indexOf("apt-get install -y --no-install-recommends git ca-certificates");
        int audit = command.indexOf("dpkg --audit");

        assertTrue(update >= 0);
        assertTrue(download > update);
        assertTrue(extract > download);
        assertTrue(preconfigure > extract);
        assertTrue(frontend > preconfigure);
        assertTrue(configure > frontend);
        assertTrue(appPackages > configure);
        assertTrue(audit > appPackages);
    }

    @Test
    public void aptRecovery_doesNotUseAptToInstallDebconfBeforeRepair() {
        String command = Debian.aptRecoveryCommand();
        assertTrue(command.contains("apt-get download debconf"));
        assertTrue(command.contains("dpkg-deb -x"));
        assertFalse(command.contains("apt-get install -y --no-install-recommends debconf"));
        assertTrue(command.contains("export DEBIAN_FRONTEND=noninteractive"));
    }


}
