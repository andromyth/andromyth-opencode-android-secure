package ai.opencode.app;

import org.junit.Test;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import static org.junit.Assert.*;

public class P53WorkspaceAttachmentsTest {
    @Test public void safeName_stripsPathsAndUnsafeCharacters() {
        assertEquals("report_final.md", WorkspaceAttachments.safeName("../../report final.md"));
        assertEquals("attachment", WorkspaceAttachments.safeName("../"));
    }

    @Test public void copyInto_placesFileInsideProjectAndPreservesBytes() throws Exception {
        File root = Files.createTempDirectory("oc-project").toFile();
        File src = File.createTempFile("source", ".md");
        byte[] bytes = "large transcript".getBytes(StandardCharsets.UTF_8);
        Files.write(src.toPath(), bytes);

        String relative = WorkspaceAttachments.copyInto(src, root);
        assertTrue(relative.startsWith("attachments/"));
        File copied = new File(root, relative);
        assertTrue(copied.isFile());
        assertArrayEquals(bytes, Files.readAllBytes(copied.toPath()));
    }

    @Test public void copyInto_neverOverwritesExistingAttachment() throws Exception {
        File root = Files.createTempDirectory("oc-project").toFile();
        File src = new File(root, "report.md");
        Files.write(src.toPath(), "first".getBytes(StandardCharsets.UTF_8));
        String first = WorkspaceAttachments.copyInto(src, root);
        Files.write(src.toPath(), "second".getBytes(StandardCharsets.UTF_8));
        String second = WorkspaceAttachments.copyInto(src, root);

        assertNotEquals(first, second);
        assertEquals("first", new String(Files.readAllBytes(new File(root, first).toPath()),
                StandardCharsets.UTF_8));
        assertEquals("second", new String(Files.readAllBytes(new File(root, second).toPath()),
                StandardCharsets.UTF_8));
    }

    @Test public void copyInto_rejectsMissingWorkspaceAndOversizeFile() throws Exception {
        File src = File.createTempFile("source", ".md");
        try {
            WorkspaceAttachments.copyInto(src, null);
            fail("missing workspace must be rejected");
        } catch (java.io.IOException expected) { }

        assertTrue(WorkspaceAttachments.MAX_FILE_BYTES == 20L * 1024L * 1024L);
    }
}
