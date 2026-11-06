package ai.opencode.app;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Imports only the user-selected SAF tree into app-private storage.
 * OpenCode receives an ordinary private filesystem path; it never receives
 * broad shared-storage permissions or a raw content URI.
 */
public final class SafWorkspace {
    private SafWorkspace() {}

    public static File importTree(Context context, Uri tree) throws Exception {
        ContentResolver resolver = context.getContentResolver();
        String rootId = DocumentsContract.getTreeDocumentId(tree);
        Uri root = DocumentsContract.buildDocumentUriUsingTree(tree, rootId);
        String display = name(resolver, root);
        String safe = display.replaceAll("[^A-Za-z0-9._ -]", "_").trim();
        if (safe.isEmpty() || ".".equals(safe) || "..".equals(safe)) safe = "imported";
        File base = new File(context.getFilesDir(), "projects");
        if (!base.exists() && !base.mkdirs()) throw new java.io.IOException("Cannot create private projects directory");
        File target = new File(base, safe);
        if (target.exists()) target = new File(base, safe + "-" + System.currentTimeMillis());
        if (!target.mkdirs()) throw new java.io.IOException("Cannot create private workspace");
        copyDirectory(resolver, tree, rootId, target, 0);
        return target;
    }

    private static String name(ContentResolver resolver, Uri document) {
        try (Cursor c = resolver.query(document,
                new String[]{DocumentsContract.Document.COLUMN_DISPLAY_NAME},
                null, null, null)) {
            if (c != null && c.moveToFirst()) return c.getString(0);
        } catch (Exception ignored) {}
        return "imported";
    }

    private static void copyDirectory(ContentResolver resolver, Uri tree,
                                      String parentId, File destination, int depth) throws Exception {
        if (depth > 64) throw new java.io.IOException("Folder nesting limit exceeded");
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId);
        String[] columns = {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE
        };
        try (Cursor c = resolver.query(children, columns, null, null, null)) {
            if (c == null) throw new java.io.IOException("Folder provider returned no listing");
            while (c.moveToNext()) {
                String id = c.getString(0);
                String raw = c.getString(1);
                String mime = c.getString(2);
                if (raw == null || raw.isEmpty() || ".".equals(raw) || "..".equals(raw)) continue;
                String leaf = raw.replace("/", "_").replace("\\", "_");
                File out = new File(destination, leaf);
                if (!out.getCanonicalPath().startsWith(destination.getCanonicalPath() + File.separator))
                    throw new java.io.IOException("Invalid document name");
                if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)) {
                    if (!out.exists() && !out.mkdirs()) throw new java.io.IOException("Cannot create " + leaf);
                    copyDirectory(resolver, tree, id, out, depth + 1);
                } else {
                    Uri fileUri = DocumentsContract.buildDocumentUriUsingTree(tree, id);
                    try (InputStream in = resolver.openInputStream(fileUri);
                         OutputStream stream = new FileOutputStream(out)) {
                        if (in == null) throw new java.io.IOException("Cannot read " + leaf);
                        byte[] buffer = new byte[64 * 1024];
                        int n;
                        while ((n = in.read(buffer)) != -1) stream.write(buffer, 0, n);
                    }
                }
            }
        }
    }
}
