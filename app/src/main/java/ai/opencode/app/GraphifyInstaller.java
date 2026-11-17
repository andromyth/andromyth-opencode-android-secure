package ai.opencode.app;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Opt-in, account-free Graphify installation in the app's existing Debian guest. */
public final class GraphifyInstaller {
    private GraphifyInstaller() {}

    public static final String VERSION = "0.9.7";
    private static final String VENV = "/opt/graphify-venv";
    private static final String PYTHON = VENV + "/bin/python";

    public static File launcher(Context c) {
        return new File(Debian.dir(c), "graphify-mcp");
    }

    public static boolean installed(Context c) {
        return new File(Debian.rootfsDir(c), "opt/graphify-venv/bin/python").isFile()
                && launcher(c).isFile();
    }

    public static boolean install(Context c, StringBuilder report) {
        if (!Debian.active(c) || !Debian.aptReady(c)) {
            append(report, "Enable and finish installing Debian 12 + apt in Settings first.");
            return false;
        }
        StringBuilder out = new StringBuilder();
        int apt = Debian.runGuest(c,
                "set -e; export DEBIAN_FRONTEND=noninteractive; "
                + "apt-get update; "
                + "apt-get install -y --no-install-recommends python3 python3-venv python3-pip",
                out, 900);
        if (apt != 0) {
            append(report, "Python prerequisite installation failed (exit " + apt + "):\n" + tail(out));
            return false;
        }

        out.setLength(0);
        String install = "set -e; "
                + "python3 -m venv " + VENV + "; "
                + PYTHON + " -m pip install --disable-pip-version-check --no-cache-dir "
                + "'graphifyy[mcp]==" + VERSION + "'; "
                + PYTHON + " -c \"import graphify, mcp, networkx; print('GRAPHIFY_IMPORT_OK')\"; "
                + PYTHON + " -m graphify.serve --help >/dev/null; "
                + "echo GRAPHIFY_MCP_CLI_OK";
        int pip = Debian.runGuest(c, install, out, 2400);
        if (pip != 0 || !out.toString().contains("GRAPHIFY_IMPORT_OK")
                || !out.toString().contains("GRAPHIFY_MCP_CLI_OK")) {
            append(report, "Graphify package/MCP smoke test failed (exit " + pip + "):\n" + tail(out));
            return false;
        }

        try {
            installSkill(c);
            writeLauncher(c);
            AuthStore.setGraphifyMcp(c, launcher(c));
        } catch (Exception e) {
            append(report, "Package installed, but skill/MCP registration failed: " + e);
            return false;
        }
        append(report, "Graphify " + VERSION + " installed. Python imports and MCP CLI smoke tests passed. "
                + "Local STDIO server is enabled; no Graphify account, OAuth, or hosted endpoint is used.");
        return true;
    }

    public static boolean disable(Context c) {
        try {
            return AuthStore.disableGraphifyMcp(c, launcher(c));
        } catch (Exception e) {
            return false;
        }
    }

    private static void installSkill(Context c) throws IOException {
        File skillRoot = new File(Binaries.homeDir(c),
                ".config/opencode/skills/graphify");
        copyAssetIfAbsent(c, "graphify/SKILL.md", new File(skillRoot, "SKILL.md"));
        File refs = new File(skillRoot, "references");
        String[] names = {"add-watch.md", "exports.md", "extraction-spec.md",
                "github-and-merge.md", "hooks.md", "query.md", "transcribe.md", "update.md"};
        for (String name : names) {
            copyAssetIfAbsent(c, "graphify/references/" + name, new File(refs, name));
        }
    }

    private static void copyAssetIfAbsent(Context c, String asset, File target)
            throws IOException {
        if (target.isFile()) return; // preserve user edits
        if (target.exists()) throw new IOException("Graphify skill path is not a file: " + target);
        File parent = target.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory())
            throw new IOException("Cannot create " + parent);
        File tmp = new File(parent, target.getName() + ".part");
        try (InputStream in = c.getAssets().open(asset);
             FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            out.getFD().sync();
        }
        if (!tmp.renameTo(target)) {
            tmp.delete();
            throw new IOException("Cannot install " + target);
        }
    }

    /**
     * OpenCode starts MCP commands as Android-host processes. This small host
     * launcher enters the existing Debian guest through proot; PWD is supplied
     * by OpenCode's per-workspace cwd, so each project gets its own graph.
     */
    private static void writeLauncher(Context c) throws IOException {
        File rootfs = Debian.rootfsDir(c);
        File bin = Debian.binDir(c);
        File lib = Debian.libDir(c);
        File home = Binaries.homeDir(c);
        File tmp = new File(Debian.dir(c), "tmp");
        if (!new File(bin, "proot").isFile() || !new File(bin, "loader").isFile()
                || !rootfs.isDirectory()) throw new IOException("Debian proot runtime is incomplete");
        if (!tmp.isDirectory() && !tmp.mkdirs() && !tmp.isDirectory())
            throw new IOException("Cannot create proot temporary directory");

        StringBuilder s = new StringBuilder();
        s.append("#!/system/bin/sh\nset -eu\n")
         .append("test -d \"$PWD\" || exit 72\n")
         .append("mkdir -p \"$PWD/graphify-out\"\n")
         .append("if [ ! -s \"$PWD/graphify-out/graph.json\" ]; then printf '%s\\n' '{\"nodes\":[],\"links\":[]}' > \"$PWD/graphify-out/graph.json\"; fi\n")
         .append("export PROOT_LOADER=").append(sh(bin.getAbsolutePath() + "/loader")).append("\n")
         .append("export PROOT_TMP_DIR=").append(sh(tmp.getAbsolutePath())).append("\n")
         .append("export LD_LIBRARY_PATH=").append(sh(lib.getAbsolutePath())).append("\n")
         .append("export PROOT_IGNORE_MISSING_BINDINGS=1 HOME=/root USER=root TMPDIR=/tmp\n")
         .append("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
         .append("exec ").append(sh(new File(bin, "proot").getAbsolutePath()))
         .append(" --rootfs=").append(sh(rootfs.getAbsolutePath()))
         .append(" --cwd=\"$PWD\" -0 --kill-on-exit --link2symlink")
         .append(" --bind=/dev --bind=/proc --bind=/sys")
         .append(" --bind=\"$PWD:$PWD\"")
         .append(" --bind=").append(sh(home.getAbsolutePath() + ":" + home.getAbsolutePath()))
         .append(" /opt/graphify-venv/bin/python -m graphify.serve")
         .append(" \"$PWD/graphify-out/graph.json\"\n");

        File target = launcher(c);
        File part = new File(target.getParentFile(), target.getName() + ".part");
        try (FileOutputStream out = new FileOutputStream(part)) {
            out.write(s.toString().getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if (target.exists() && !target.delete()) throw new IOException("Cannot replace Graphify launcher");
        if (!part.renameTo(target)) throw new IOException("Cannot write Graphify launcher");
        Binaries.makeExec(target);
    }

    private static String sh(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String tail(StringBuilder b) {
        String s = b == null ? "" : b.toString().trim();
        return s.length() <= 5000 ? s : s.substring(s.length() - 5000);
    }

    private static void append(StringBuilder out, String value) {
        if (out != null) out.append(value);
    }
}
