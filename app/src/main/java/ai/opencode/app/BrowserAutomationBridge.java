package ai.opencode.app;

import android.view.accessibility.AccessibilityEvent;

public final class BrowserAutomationBridge {
    private BrowserAutomationBridge() {}

    public static boolean connected() {
        return BrowserAutomationService.connected();
    }

    public static void openUrl(String url) {
        BrowserAutomationService s = BrowserAutomationService.instance();
        if (s != null) s.openUrl(url);
    }

    public static void click(String query) {
        BrowserAutomationService s = BrowserAutomationService.instance();
        if (s != null) s.click(query);
    }

    public static void typeInto(String query, String text) {
        BrowserAutomationService s = BrowserAutomationService.instance();
        if (s != null) s.typeInto(query, text);
    }

    public static String read() {
        BrowserAutomationService s = BrowserAutomationService.instance();
        return s == null ? "" : s.read();
    }

    public static void pressBack() {
        BrowserAutomationService s = BrowserAutomationService.instance();
        if (s != null) s.pressBack();
    }

    public static void pressHome() {
        BrowserAutomationService s = BrowserAutomationService.instance();
        if (s != null) s.pressHome();
    }

    static void onConnected(BrowserAutomationService s) {}
    static void onDisconnected() {}
    static void onEvent(AccessibilityEvent e) {}
}
