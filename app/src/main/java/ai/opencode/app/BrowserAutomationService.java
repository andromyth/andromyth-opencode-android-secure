package ai.opencode.app;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Toast;

import java.lang.ref.WeakReference;
import java.util.ArrayDeque;

public class BrowserAutomationService extends AccessibilityService {
    private static WeakReference<BrowserAutomationService> SERVICE =
            new WeakReference<>(null);
    private static Handler MAIN;

    public static BrowserAutomationService instance() {
        return SERVICE == null ? null : SERVICE.get();
    }

    public static boolean connected() {
        return instance() != null;
    }

    public static void enqueue(Runnable cmd) {
        Handler h = MAIN;
        if (h != null) h.post(cmd);
    }

    private volatile String lastText = "";

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        SERVICE = new WeakReference<>(this);
        MAIN = new Handler(Looper.getMainLooper());
        BrowserAutomationBridge.onConnected(this);
        Toast.makeText(this, "browser automation connected", Toast.LENGTH_SHORT)
                .show();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        SERVICE = new WeakReference<>(null);
        MAIN = null;
        BrowserAutomationBridge.onDisconnected();
        return super.onUnbind(intent);
    }

    @Override
    public void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent event) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root != null) {
            String t = textOf(root);
            lastText = t == null ? "" : t;
        }
        BrowserAutomationBridge.onEvent(event);
    }

    @Override
    public void onInterrupt() {
        lastText = "";
    }

    public void openUrl(String url) {
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception e) {
            Toast.makeText(this, "could not open " + url, Toast.LENGTH_SHORT).show();
        }
    }

    public void click(String query) {
        enqueue(() -> {
            AccessibilityNodeInfo root = getRootInActiveWindow();
            if (root == null) return;
            AccessibilityNodeInfo n = find(root, query, false);
            if (n != null) {
                if (!n.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                    n.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
                }
            }
        });
    }

    public void typeInto(String query, String text) {
        enqueue(() -> {
            AccessibilityNodeInfo root = getRootInActiveWindow();
            if (root == null) return;
            AccessibilityNodeInfo n = find(root, query, true);
            if (n == null) return;
            n.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
            Bundle args = new Bundle();
            args.putCharSequence(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text);
            n.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args);
        });
    }

    public void pressBack() {
        performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK);
    }

    public void pressHome() {
        performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME);
    }

    public String read() {
        return lastText;
    }

    private static String textOf(android.view.accessibility.AccessibilityNodeInfo n) {
        if (n == null) return null;
        CharSequence t = n.getText();
        String s = t == null ? "" : t.toString();
        for (int i = 0; i < n.getChildCount(); i++) {
            android.view.accessibility.AccessibilityNodeInfo c = n.getChild(i);
            if (c != null) {
                String ct = textOf(c);
                if (ct != null && !ct.isEmpty()) {
                    if (!s.isEmpty()) s += "\n";
                    s += ct;
                }
            }
        }
        return s;
    }

    private static AccessibilityNodeInfo find(AccessibilityNodeInfo root,
                                              String query, boolean editable) {
        if (root == null) return null;
        String q = query == null ? "" : query.toLowerCase();
        ArrayDeque<AccessibilityNodeInfo> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            AccessibilityNodeInfo n = stack.pop();
            if (n == null) continue;
            CharSequence txt = n.getText();
            CharSequence desc = n.getContentDescription();
            String t = (txt == null ? "" : txt.toString()) + " "
                    + (desc == null ? "" : desc.toString());
            boolean match = q.isEmpty() || t.toLowerCase().contains(q);
            if (match) {
                boolean isEditable = n.isEditable()
                        || "android.widget.EditText".equals(n.getClassName())
                        || n.isFocusable();
                if (!editable || isEditable) return n;
            }
            for (int i = n.getChildCount() - 1; i >= 0; i--) {
                AccessibilityNodeInfo c = n.getChild(i);
                if (c != null) stack.push(c);
            }
        }
        return null;
    }
}
