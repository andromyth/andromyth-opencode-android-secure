package ai.opencode.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class CaptureActivity extends Activity {

    private static final int REQ_VPN = 61;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView tvStatus;
    private TextView tvList;
    private TextView chipStart;
    private boolean showing = true;

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            if (!showing) return;
            paint();
            ui.postDelayed(this, 1500);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Theme.cr(this, R.color.bg));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, dp(32));
        scroll.addView(root);
        setContentView(scroll);
        Theme.window(this);

        root.addView(header());

        root.addView(section("capture"));
        tvStatus = monoText();
        root.addView(tvStatus);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        chipStart = chip("Start");
        chipStart.setOnClickListener(v -> start());
        TextView stop = chip("Stop");
        stop.setTextColor(Theme.cr(this, R.color.err));
        stop.setOnClickListener(v -> stop());
        row.addView(chipStart);
        row.addView(stop);
        root.addView(row);

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        TextView clear = chip("Clear");
        clear.setOnClickListener(v -> {
            CaptureStore.clear();
            paint();
        });
        TextView export = chip("Export");
        export.setOnClickListener(v -> export());
        TextView copy = chip("Copy");
        copy.setOnClickListener(v -> copy());
        row2.addView(clear);
        row2.addView(export);
        row2.addView(copy);
        root.addView(row2);

        root.addView(section("domains"));
        tvList = monoText();
        root.addView(tvList);
        root.addView(note("DNS-only capture: the VPN hands the system a local "
                + "resolver, forwards every lookup upstream, and records the "
                + "question name. Normal traffic is NOT routed through the "
                + "tunnel, so speed and connectivity are unchanged. Encrypted "
                + "DNS (Private DNS / DoH) and apps that ship their own resolver "
                + "are invisible here. One VPN at a time: disconnect any other "
                + "VPN first."));
        paint();
    }

    @Override
    protected void onResume() {
        super.onResume();
        Theme.syncIfNeeded(this);
        showing = true;
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        showing = false;
        ui.removeCallbacks(tick);
        super.onPause();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_VPN) return;
        if (res == RESULT_OK) launch();
        else Toast.makeText(this, "VPN permission denied", Toast.LENGTH_LONG).show();
    }

    private void start() {
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
            return;
        }
        launch();
    }

    private void launch() {
        Intent i = new Intent(this, CaptureService.class)
                .setAction(CaptureService.ACTION_START);
        startForegroundService(i);
    }

    private void stop() {
        Intent i = new Intent(this, CaptureService.class)
                .setAction(CaptureService.ACTION_STOP);
        startService(i);
    }

    private void paint() {
        boolean on = CaptureService.running();
        StringBuilder sb = new StringBuilder();
        sb.append(on ? "● capturing" : "○ off");
        if (on) {
            sb.append(" · ").append(CaptureStore.total()).append(" queries · ")
              .append(CaptureStore.size()).append(" domains");
            long t = CaptureStore.startedAt();
            if (t > 0) {
                long s = Math.max(0, (System.currentTimeMillis() - t) / 1000);
                sb.append(" · ").append(s).append("s");
            }
        }
        String err = CaptureService.lastError();
        if (err != null && !err.isEmpty()) sb.append("\n").append(err);
        tvStatus.setText(sb.toString());
        tvList.setText(CaptureStore.display(500));
        chipStart.setText(on ? "Restart" : "Start");
    }

    private void export() {
        try {
            File f = new File(Binaries.homeDir(this), "capture-domains.tsv");
            try (FileOutputStream o = new FileOutputStream(f)) {
                o.write(CaptureStore.dump().getBytes(StandardCharsets.UTF_8));
            }
            Toast.makeText(this, f.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (Throwable t) {
            Toast.makeText(this, "export failed: " + t, Toast.LENGTH_LONG).show();
        }
    }

    private void copy() {
        try {
            String body = CaptureStore.display(2000);
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("opencode capture", body));
            Toast.makeText(this, "domain list copied", Toast.LENGTH_SHORT).show();
        } catch (Throwable t) {
            Toast.makeText(this, "copy failed: " + t, Toast.LENGTH_SHORT).show();
        }
    }

    private LinearLayout header() {
        LinearLayout h = new LinearLayout(this);
        h.setOrientation(LinearLayout.HORIZONTAL);
        h.setGravity(Gravity.CENTER_VERTICAL);
        TextView back = text(20, R.color.accent_light, false);
        back.setText("‹");
        back.setPadding(0, 0, dp(18), 0);
        back.setOnClickListener(v -> finish());
        h.addView(back);
        TextView title = text(18, R.color.text_primary, true);
        title.setText("Net capture");
        h.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return h;
    }

    private TextView section(String s) {
        TextView t = text(11, R.color.text_secondary, true);
        t.setText(s.toUpperCase());
        t.setPadding(0, dp(18), 0, dp(6));
        return t;
    }

    private TextView chip(String label) {
        TextView t = text(13, R.color.text_primary, false);
        t.setText(label);
        t.setBackgroundResource(R.drawable.bg_chip);
        int p = dp(12);
        t.setPadding(p, dp(8), p, dp(8));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = dp(8);
        t.setLayoutParams(lp);
        return t;
    }

    private TextView note(String s) {
        TextView t = text(12, R.color.text_secondary, false);
        t.setText(s);
        t.setPadding(0, dp(8), 0, 0);
        return t;
    }

    private TextView monoText() {
        TextView t = new TextView(this);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(11);
        t.setTextColor(Theme.cr(this, R.color.text_primary));
        t.setBackgroundColor(Theme.cr(this, R.color.surface));
        int p = dp(10);
        t.setPadding(p, p, p, p);
        t.setTextIsSelectable(true);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        t.setLayoutParams(lp);
        return t;
    }

    private TextView text(int sizeSp, int colorRes, boolean bold) {
        TextView tv = new TextView(this);
        tv.setTextSize(sizeSp);
        tv.setTextColor(Theme.cr(this, colorRes));
        if (bold) tv.setTypeface(Typeface.DEFAULT_BOLD);
        return tv;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
