package ai.opencode.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Copies non-image attachments into the active OpenCode project workspace.
 * The agent can then inspect large documents with its normal file tools
 * instead of receiving the entire document as a base64 media part.
 */
public final class WorkspaceAttachments {
    public static final long MAX_FILE_BYTES = 20L * 1024L * 1024L;
    public static final long MAX_BATCH_BYTES = 50L * 1024L * 1024L;

    private WorkspaceAttachments() {}

    public static String safeName(String name) {
        String value = name == null ? "" : name.trim();
        int slash = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\\\'));
        if (slash >= 0) value = value.substring(slash + 1);
        value = value.replaceAll("[^A-Za-z0-9._-]", "_");
        while (value.startsWith(".")) value = value.substring(1);
        if (value.isEmpty()) value = "attachment";
        if (value.length() > 100) {
            int dot = value.lastIndexOf('.');
            String ext = dot > 0 && value.length() - dot <= 12
                    ? value.substring(dot) : "";
            value = value.substring(0, Math.min(88, value.length() - ext.length())) + ext;
        }
        return value;
    }

    /** Copy one file atomically; return its project-relative path. */
    public static String copyInto(File source, File projectRoot) throws IOException {
        if (source == null || !source.isFile())
            throw new IOException("attachment is no longer available");
        long size = source.length();
        if (size > MAX_FILE_BYTES)
            throw new IOException(source.getName() + " exceeds 20 MB");

        if (projectRoot == null || !projectRoot.isDirectory())
            throw new IOException("the active project workspace is unavailable");

        File root = projectRoot.getCanonicalFile();
        File dir = new File(root, "attachments");
        if (!dir.exists() && !dir.mkdirs())
            throw new IOException("could not create project attachments folder");
        dir = dir.getCanonicalFile();
        if (!dir.getPath().startsWith(root.getPath() + File.separator))
            throw new IOException("attachments folder escaped the project root");

        String base = safeName(source.getName());
        String stem = base;
        String ext = "";
        int dot = base.lastIndexOf('.');
        if (dot > 0) { stem = base.substring(0, dot); ext = base.substring(dot); }

        File target = null;
        for (int i = 0; i < 100; i++) {
            String suffix = i == 0 ? "" : "_" + System.currentTimeMillis() + "_" + i;
            File candidate = new File(dir, stem + suffix + ext);
            if (!candidate.exists()) { target = candidate; break; }
        }
        if (target == null) throw new IOException("could not allocate a unique attachment name");

        File temp = File.createTempFile(".oc-attach-", ".tmp", dir);
        boolean moved = false;
        try {
            try (InputStream in = new FileInputStream(source);
                 OutputStream out = new FileOutputStream(temp)) {
                byte[] buffer = new byte[32 * 1024];
                int n;
                while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
            }
            if (!temp.renameTo(target))
                throw new IOException("could not commit attachment into project");
            moved = true;
            return "attachments/" + target.getName();
        } finally {
            if (!moved) temp.delete();
        }
    }
}
