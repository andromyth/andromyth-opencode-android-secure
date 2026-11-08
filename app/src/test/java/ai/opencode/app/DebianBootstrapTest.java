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
    public void aptReady_requiresMarkerGitPerlDebconfAndCaFiles() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        File debian = Debian.dir(context);
        File root = Debian.rootfsDir(context);
        File marker = new File(debian, ".apt-ready");
        File git = new File(root, "usr/bin/git");
        File perl = new File(root, "usr/bin/perl");
        File frontend = new File(root, "usr/share/debconf/frontend");
        File preconfigure = new File(root, "usr/sbin/dpkg-preconfigure");
        File ca = new File(root, "etc/ssl/certs/ca-certificates.crt");

        marker.getParentFile().mkdirs();
        git.getParentFile().mkdirs();
        perl.getParentFile().mkdirs();
        frontend.getParentFile().mkdirs();
        preconfigure.getParentFile().mkdirs();
        ca.getParentFile().mkdirs();

        marker.delete();
        git.delete();
        perl.delete();
        frontend.delete();
        preconfigure.delete();
        ca.delete();
        assertFalse(Debian.aptReady(context));

        try (FileOutputStream out = new FileOutputStream(marker)) {
            out.write("verified\\n".getBytes("UTF-8"));
        }
        try (FileOutputStream out = new FileOutputStream(git)) {
            out.write(new byte[] {1});
        }
        try (FileOutputStream out = new FileOutputStream(ca)) {
            out.write(new byte[] {1});
        }
        assertFalse(Debian.aptReady(context));

        try (FileOutputStream out = new FileOutputStream(perl)) {
            out.write(new byte[] {1});
        }
        try (FileOutputStream out = new FileOutputStream(frontend)) {
            out.write(new byte[] {1});
        }
        try (FileOutputStream out = new FileOutputStream(preconfigure)) {
            out.write(new byte[] {1});
        }
        assertTrue(Debian.aptReady(context));
    }

    @Test
    public void aptRecovery_extractsDebconfAndPerlBeforeDpkgConfiguration() {
        String command = Debian.aptRecoveryCommand();
        int update = command.indexOf("apt-get update");
        int download = command.indexOf("apt-get download debconf perl-base");
        int extract = command.indexOf("dpkg-deb -x");
        int perl = command.indexOf("test -x /usr/bin/perl");
        int runtime = command.indexOf("/usr/bin/perl -e");
        int preconfigure = command.indexOf("test -x /usr/sbin/dpkg-preconfigure");
        int frontend = command.indexOf("test -x /usr/share/debconf/frontend");
        int configure = command.indexOf("dpkg --configure -a");
        int appPackages = command.indexOf("apt-get install -y --no-install-recommends git ca-certificates");
        int audit = command.indexOf("dpkg --audit");

        assertTrue(update >= 0);
        assertTrue(download > update);
        assertTrue(extract > download);
        assertTrue(perl > extract);
        assertTrue(preconfigure > perl);
        assertTrue(frontend > preconfigure);
        assertTrue(runtime > frontend);
        assertTrue(configure > runtime);
        assertTrue(appPackages > configure);
        assertTrue(audit > appPackages);
    }

    @Test
    public void aptRecovery_restoresPerlBaseWithoutAptConfiguringBrokenPackages() {
        String command = Debian.aptRecoveryCommand();
        assertTrue(command.contains("apt-get download debconf perl-base"));
        assertTrue(command.contains("dpkg-deb -x"));
        assertTrue(command.contains("/usr/bin/perl -e"));
        assertFalse(command.contains("apt-get install -y --no-install-recommends debconf"));
        assertTrue(command.contains("export DEBIAN_FRONTEND=noninteractive"));
    }

}
