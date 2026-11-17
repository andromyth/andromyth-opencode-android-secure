package ai.opencode.app;

import android.view.View;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * P14: inflate the real chat screen and verify the spend pill exists,
 * starts hidden, and the picker-related state pieces are wired. Runs the
 * ACTIVITY through Robolectric so a layout/ID typo fails here, not on the
 * user's device.
 */
@RunWith(RobolectricTestRunner.class)
public class ChatLayoutTest {

    @Test
    public void chatInflates_withSpendPill() {
        try (ActivityController<ChatActivity> ctl =
                     Robolectric.buildActivity(ChatActivity.class)) {
            ChatActivity a = ctl.setup().get();   // create + start + resume
            TextView spend = a.findViewById(R.id.tvSpend);
            assertNotNull("tvSpend must exist in activity_chat.xml", spend);
            assertEquals("spend pill hidden until there is spend",
                    View.GONE, spend.getVisibility());
            TextView sub = a.findViewById(R.id.tvSub);
            assertNotNull(sub);
            assertTrue(sub.getText().length() > 0);
            // P17: the vision chip must exist in the composer
            assertNotNull("btnVision must exist in activity_chat.xml",
                    a.findViewById(R.id.btnVision));
        }
    }

    /** P29: the composer grew upward — the attachment tray and the cost
     *  hint must exist and BOTH sit between the typing dots and the text
     *  input (the tray is composerBar's FIRST child, the hint the LAST
     *  before the input row). A regression that reorders the composer
     *  (P28's drifting-dots lesson) fails here, not on the device. */
    @Test
    public void p29_composer_trayAndCostHint_declaredAboveInput() {
        try (ActivityController<ChatActivity> ctl =
                     Robolectric.buildActivity(ChatActivity.class)) {
            ChatActivity a = ctl.setup().get();
            View attachScroll = a.findViewById(R.id.attachScroll);
            View costHint = a.findViewById(R.id.costHint);
            View composerBar = a.findViewById(R.id.composerBar);
            View input = a.findViewById(R.id.input);
            View typingSlot = a.findViewById(R.id.typingSlot);
            assertNotNull(attachScroll);
            assertNotNull(costHint);
            assertNotNull(composerBar);
            assertNotNull(input);
            assertEquals("tray hidden until an image is picked",
                    View.GONE, attachScroll.getVisibility());
            assertEquals("cost hint hidden until there is something to send",
                    View.GONE, costHint.getVisibility());
            // order in the root column: typing dots ABOVE the whole composer
            android.view.ViewGroup root = (android.view.ViewGroup) composerBar.getParent();
            assertTrue("typing dots above the composer",
                    root.indexOfChild(typingSlot) < root.indexOfChild(composerBar));
            // inside the composer: the cost hint first, then the pill
            // (composerCard) holding tray → borderless input → controls row
            android.view.ViewGroup bar = (android.view.ViewGroup) composerBar;
            android.view.ViewGroup pill = (android.view.ViewGroup)
                    a.findViewById(R.id.composerCard);
            assertEquals(costHint, bar.getChildAt(0));
            assertEquals(pill, bar.getChildAt(1));
            assertEquals("the pill holds tray, input, controls row",
                    3, pill.getChildCount());
            assertEquals(attachScroll, pill.getChildAt(0));
            assertEquals("the input floats borderless inside the pill",
                    input, pill.getChildAt(1));
            View controls = pill.getChildAt(2);
            assertNotNull("send lives in the pill's controls row",
                    controls.findViewById(R.id.btnSend));
            assertNotNull("the model chip lives in the pill's controls row",
                    controls.findViewById(R.id.chipModel));
        }
    }
    /** Long permission payloads scroll independently; action targets keep equal width. */
    @Test
    public void permissionCard_largeCommandKeepsActionsVisible() throws Exception {
        try (ActivityController<ChatActivity> ctl =
                     Robolectric.buildActivity(ChatActivity.class)) {
            ChatActivity a = ctl.setup().get();
            java.util.Map<String, Object> metadata = new java.util.HashMap<>();
            metadata.put("command", new String(new char[8000]).replace('\0', 'x'));
            java.util.Map<String, Object> permission = new java.util.HashMap<>();
            permission.put("id", "permission-test");
            permission.put("permission", "external_directory");
            permission.put("metadata", metadata);

            java.lang.reflect.Method build = ChatActivity.class.getDeclaredMethod(
                    "buildPermCard", java.util.Map.class);
            build.setAccessible(true);
            android.view.View card = (android.view.View) build.invoke(a, permission);
            android.view.ViewGroup content = (android.view.ViewGroup) card;
            ScrollView preview = (ScrollView) content.getChildAt(1);
            TextView previewText = (TextView) preview.getChildAt(0);
            android.view.ViewGroup actions =
                    (android.view.ViewGroup) content.getChildAt(2);

            assertTrue("preview viewport has a fixed height",
                    preview.getLayoutParams().height > 0);
            assertTrue("full preview remains independently scrollable",
                    previewText.getText().length() > 1000);
            assertTrue("preview text remains selectable", previewText.isTextSelectable());
            assertEquals(3, actions.getChildCount());
            for (int i = 0; i < actions.getChildCount(); i++) {
                LinearLayout.LayoutParams lp =
                        (LinearLayout.LayoutParams) actions.getChildAt(i).getLayoutParams();
                assertEquals("all actions share the available width", 1f, lp.weight, 0f);
            }
        }
    }

    /** Question cards bound their content viewport and keep actions outside the scroll area. */
    @Test
    public void questionCard_longContentScrollsWhileActionsStayVisible() throws Exception {
        try (ActivityController<ChatActivity> ctl =
                     Robolectric.buildActivity(ChatActivity.class)) {
            ChatActivity a = ctl.setup().get();
            java.util.List<Questions.Opt> options = new java.util.ArrayList<>();
            options.add(new Questions.Opt("Forecast the 15:30 close", null));
            options.add(new Questions.Opt("Show a 5-min path to 15:30", null));
            java.util.List<Questions.Prompt> prompts = new java.util.ArrayList<>();
            for (int i = 0; i < 3; i++) {
                prompts.add(new Questions.Prompt("Question " + i, "Target", false, options));
            }
            Questions.Req req = new Questions.Req("question-scroll-test", "session-test", prompts);
            java.lang.reflect.Method build = ChatActivity.class.getDeclaredMethod(
                    "buildQuestionCard", Questions.Req.class);
            build.setAccessible(true);
            LinearLayout card = (LinearLayout) build.invoke(a, req);

            assertEquals("header, bounded content, fixed actions", 3, card.getChildCount());
            ScrollView content = (ScrollView) card.getChildAt(1);
            assertTrue("question content has a bounded viewport",
                    content.getLayoutParams().height > 0);
            assertTrue("vertical scrollbar is enabled", content.isVerticalScrollBarEnabled());
            LinearLayout contentBody = (LinearLayout) content.getChildAt(0);
            assertTrue("all question sections remain in the scroll body",
                    contentBody.getChildCount() > 3);
            assertEquals("actions remain outside the scroll view",
                    "Skip", ((TextView) ((LinearLayout) card.getChildAt(2)).getChildAt(0)).getText().toString());
            HorizontalScrollView optionsScroll =
                    (HorizontalScrollView) contentBody.getChildAt(2);
            assertTrue("long option rows can scroll horizontally",
                    optionsScroll.isHorizontalScrollBarEnabled());
        }
    }

    /** Returning from another app must repaint a permission already in the process queue. */
    @Test
    public void resume_rebuildsPendingPermissionCard() throws Exception {
        java.lang.reflect.Field field = ServerService.class.getDeclaredField("PERMS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Queue<java.util.Map<String, Object>> queue =
                (java.util.Queue<java.util.Map<String, Object>>) field.get(null);
        queue.clear();
        java.util.Map<String, Object> metadata = new java.util.HashMap<>();
        metadata.put("command", "pwd");
        java.util.Map<String, Object> permission = new java.util.HashMap<>();
        permission.put("id", "resume-permission-test");
        permission.put("permission", "external_directory");
        permission.put("metadata", metadata);
        queue.add(permission);
        try (ActivityController<ChatActivity> ctl =
                     Robolectric.buildActivity(ChatActivity.class)) {
            ChatActivity a = ctl.setup().get();
            android.view.View slot = a.findViewById(R.id.permSlot);
            assertEquals(View.VISIBLE, slot.getVisibility());
            ctl.pause().resume();
            org.robolectric.Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();
            assertEquals("permission card is restored after background/resume",
                    View.VISIBLE, slot.getVisibility());
            assertEquals(1, ((android.view.ViewGroup) slot).getChildCount());
        } finally {
            queue.clear();
        }
    }

}
