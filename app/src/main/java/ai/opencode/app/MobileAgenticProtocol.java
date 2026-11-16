package ai.opencode.app;

/**
 * Compatibility pass-through for user messages. Mobile Agentic Master is
 * installed as an OpenCode skill; it must not be injected into chat text.
 */
public final class MobileAgenticProtocol {
    private MobileAgenticProtocol() {}

    public static final String VERSION = "2.0.0";

    public static String wrap(String userText) {
        return userText;
    }
}
