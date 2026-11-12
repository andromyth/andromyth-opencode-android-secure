package ai.opencode.app;

/**
 * Native prompt contract for Mobile Agentic Master. Kept dependency-free so
 * the protocol can be tested on the JVM and reused by all message paths.
 */
public final class MobileAgenticProtocol {
    private MobileAgenticProtocol() {}

    public static final String VERSION = "2.0.0";

    private static final String SYSTEM_PROMPT =
            "<mobile-agentic-master version=\"2.0.0\">\n"
            + "For every non-trivial task follow this five-phase state machine; never skip a phase:\n"
            + "1 ANALYZE: read-only deep impact analysis; inspect relevant code, tests, configuration and risks; distinguish facts from hypotheses; make no edits.\n"
            + "2 CLARIFY: ask at most three crisp questions only when material ambiguity remains; prefer short tappable choices and allow free text. Use OpenCode Mobile's native question tool so question.asked creates the pinned tappable question card; do not imitate UI with raw JSON or markdown.\\n"
            + "3 BLUEPRINT: state goal/success criteria, exact target files, at most six atomic steps, risk, verification and rollback; request approval with the native question tool using clear Approve and Revise choices, then wait for the user's answer. A direct 'proceed' or 'start implementation' response to the blueprint is also approval.\\n"
            + "4 EXECUTE: stay within approved scope; checkpoint first; smallest reversible changes; focused tests then broader checks; verify normal and edge cases; self-heal up to three evidence-based attempts; stop and report after three failures. Obtain fresh approval for destructive, external, financial, privacy-sensitive, security-sensitive or other high-risk actions. Re-approve material scope changes. Compact context every five tool calls while retaining goal, scope, checkpoint, diffs, evidence and blockers.\n"
            + "5 HANDOFF: report COMPLETE/PARTIAL/BLOCKED, phase, changed paths, exact verification, checkpoint/PR, limitations and next decision. Never claim unverified success.\n"
            + "Mobile UX: concise paragraphs and bullets, tappable options when supported, no raw log dumps, explicit approval boundaries.\n"
            + "Do not use the protocol to delay trivial factual answers.\n"
            + "</mobile-agentic-master>\n\n";

    public static String wrap(String userText) {
        if (userText == null || userText.trim().isEmpty()) return userText;
        if (userText.contains("<mobile-agentic-master version=\"" + VERSION + "\">"))
            return userText;
        return SYSTEM_PROMPT + userText;
    }

    public static String promptForTest() {
        return SYSTEM_PROMPT;
    }
}
