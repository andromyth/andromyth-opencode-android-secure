package ai.opencode.app;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.LinkedHashMap;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Live passive ARP neighbour-cache monitor with offline detector simulations.
 * Reads the kernel ARP cache only; never sends packets or changes network state.
 */
public final class ArpSecurityLabActivity extends Activity {
    private LinearLayout history;
    private TextView status;
    private int runCount;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private boolean monitoring;
    private ArpSpoofLab.Detector liveDetector;
    private final Runnable livePoll = new Runnable() { @Override public void run() { pollLive(); if (monitoring) handler.postDelayed(this, 3000L); } };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Theme.cr(this, R.color.bg));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = Theme.dp(this, 16);
        root.setPadding(pad, pad, pad, Theme.dp(this, 28));
        scroll.addView(root);
        setContentView(scroll);
        Theme.window(this);

        TextView title = new TextView(this);
        title.setText("ARP security monitor");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView boundary = new TextView(this);
        boundary.setText("LIVE MODE: read-only sampling of Android /proc/net/arp. No packets are sent and no network settings are changed. Android or OEM policy may deny access; if blocked, the app reports live monitoring unavailable. Mapping changes are warnings for investigation, not proof of spoofing. Offline simulations remain available below.");
        boundary.setTextSize(12);
        boundary.setTextColor(Theme.TXT_DIM);
        boundary.setPadding(0, Theme.dp(this, 8), 0, Theme.dp(this, 10));
        root.addView(boundary);

        status = new TextView(this);
        status.setText("No scenarios run yet.");
        status.setTextSize(13);
        status.setTextColor(Theme.TXT);
        root.addView(status);

        root.addView(action("Start live passive monitoring", v -> {
            monitoring = true;
            liveDetector = null;
            handler.removeCallbacks(livePoll);
            livePoll.run();
        }));
        root.addView(action("Stop live monitoring", v -> {
            monitoring = false;
            handler.removeCallbacks(livePoll);
            status.setText("Live monitoring stopped.");
        }));
        root.addView(action("Take one live snapshot", v -> pollLive()));
        root.addView(action("Run normal network scenario", v ->
                run(ArpSpoofLab.Scenario.NORMAL)));
        root.addView(action("Simulate gateway MAC change", v ->
                run(ArpSpoofLab.Scenario.GATEWAY_MAC_CHANGE)));
        root.addView(action("Simulate duplicate IP claim", v ->
                run(ArpSpoofLab.Scenario.DUPLICATE_IP_CLAIM)));
        root.addView(action("Run all scenarios", v -> {
            run(ArpSpoofLab.Scenario.NORMAL);
            run(ArpSpoofLab.Scenario.GATEWAY_MAC_CHANGE);
            run(ArpSpoofLab.Scenario.DUPLICATE_IP_CLAIM);
        }));
        root.addView(action("Clear alert history", v -> {
            history.removeAllViews();
            runCount = 0;
            status.setText("History cleared. No scenarios run yet.");
        }));

        TextView historyTitle = new TextView(this);
        historyTitle.setText("Live alerts and simulation history");
        historyTitle.setTextSize(18);
        historyTitle.setTextColor(Theme.TXT);
        historyTitle.setPadding(0, Theme.dp(this, 20), 0, Theme.dp(this, 4));
        root.addView(historyTitle);

        history = new LinearLayout(this);
        history.setOrientation(LinearLayout.VERTICAL);
        root.addView(history);
    }


    private void pollLive() {
        status.setText("Checking Android neighbour-table access…");
        io.execute(() -> {
            try {
                Map<String,String> snapshot = ArpNeighbourMonitor.readSnapshot();
                handler.post(() -> applyLiveSnapshot(snapshot));
            } catch (IOException | SecurityException e) {
                handler.post(() -> showLiveUnavailable(e));
            } catch (RuntimeException e) {
                handler.post(() -> showLiveUnavailable(e));
            }
        });
    }

    private void applyLiveSnapshot(Map<String,String> snapshot) {
        if (isFinishing() || isDestroyed()) return;
        if (snapshot.isEmpty()) {
            status.setText("ACCESSIBLE · No complete IPv4 ARP entries are currently exposed. This is not proof that the LAN is clean.");
        } else if (liveDetector == null) {
            liveDetector = new ArpSpoofLab.Detector(new LinkedHashMap<>(snapshot));
            addLiveCard("LIVE BASELINE", "Captured " + snapshot.size() + " complete IP-to-MAC bindings.");
            status.setText("LIVE · Baseline captured: " + snapshot.size() + " entries.");
        } else {
            StringBuilder changes = new StringBuilder();
            int count = 0;
            for (Map.Entry<String,String> entry : snapshot.entrySet()) {
                for (ArpSpoofLab.Alert alert : liveDetector.observe(
                        new ArpSpoofLab.Observation(entry.getKey(), entry.getValue()))) {
                    count++;
                    changes.append(alert.type).append(" · ").append(alert.ip)
                            .append(" · expected ").append(alert.expectedMac)
                            .append(" · observed ").append(alert.observedMac).append('\\n');
                }
            }
            status.setText("LIVE · " + snapshot.size() + " entries · "
                    + (count == 0 ? "no new mapping-change warnings" : count + " new warnings"));
            if (count > 0) addLiveCard("POSSIBLE ARP ANOMALY — VERIFY", changes.toString().trim());
        }
        if (monitoring) handler.postDelayed(livePoll, 3000L);
    }

    private void showLiveUnavailable(Exception error) {
        if (isFinishing() || isDestroyed()) return;
        monitoring = false;
        handler.removeCallbacks(livePoll);
        status.setText("LIVE MONITOR UNAVAILABLE · Android blocked or failed neighbour-table access: "
                + error.getClass().getSimpleName() + ". No live ARP visibility is available through this method.");
        addLiveCard("LIVE ACCESS UNAVAILABLE", error.toString());
    }

    private void addLiveCard(String label, String detail) {
        TextView card = new TextView(this);
        card.setText(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date())
                + " · " + label + "\n" + detail
                + "\nRead-only cache observation; mapping changes are not proof of spoofing.");
        card.setTextSize(12);
        card.setTextColor(Theme.TXT);
        card.setPadding(Theme.dp(this, 12), Theme.dp(this, 12), Theme.dp(this, 12), Theme.dp(this, 12));
        history.addView(card, 0);
    }

    @Override protected void onPause() {
        monitoring = false;
        handler.removeCallbacks(livePoll);
        super.onPause();
    }

    @Override protected void onDestroy() {
        handler.removeCallbacks(livePoll);
        io.shutdownNow();
        super.onDestroy();
    }

    private TextView action(String label, View.OnClickListener listener) {
        TextView v = new TextView(this);
        v.setText(label);
        v.setTextSize(14);
        v.setTextColor(Theme.TXT);
        v.setPadding(Theme.dp(this, 14), Theme.dp(this, 13),
                Theme.dp(this, 14), Theme.dp(this, 13));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Theme.cr(this, R.color.surface));
        bg.setCornerRadius(Theme.dp(this, 12));
        v.setBackground(bg);
        v.setOnClickListener(listener);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Theme.dp(this, 8);
        v.setLayoutParams(lp);
        return v;
    }

    private void run(ArpSpoofLab.Scenario scenario) {
        ArpSpoofLab.ScenarioResult result = ArpSpoofLab.runScenario(scenario);
        runCount++;
        boolean detected = !result.alerts.isEmpty();
        String severity = detected ? "HIGH · SIMULATED ANOMALY" : "INFO · NORMAL";
        status.setText("Runs: " + runCount + "  |  Latest: "
                + (detected ? result.alerts.size() + " simulated alerts" : "no alerts"));
        addHistoryCard(scenario, severity, result);
    }

    private void addHistoryCard(ArpSpoofLab.Scenario scenario, String severity,
            ArpSpoofLab.ScenarioResult result) {
        TextView card = new TextView(this);
        StringBuilder text = new StringBuilder();
        text.append(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()))
                .append("  ·  ").append(severity).append('\n');
        text.append(scenario.name()).append('\n');
        text.append("Synthetic observations: ").append(result.observations.size()).append('\n');
        for (ArpSpoofLab.Observation observation : result.observations) {
            text.append("  ").append(observation.ip).append("  →  ")
                    .append(observation.mac).append('\n');
        }
        if (result.alerts.isEmpty()) {
            text.append("No anomalies detected in this synthetic scenario.");
        } else {
            for (ArpSpoofLab.Alert alert : result.alerts) {
                text.append("• ").append(alert.type.name()).append(" · ")
                        .append(alert.ip);
                if (alert.expectedMac != null)
                    text.append(" · expected ").append(alert.expectedMac);
                text.append(" · observed ").append(alert.observedMac).append('\n');
            }
        }
        text.append("\n[SIMULATED DATA — NOT A LIVE NETWORK ALERT]");
        card.setText(text.toString());
        card.setTextSize(12);
        card.setTextColor(Theme.TXT);
        card.setTypeface(Typeface.MONOSPACE);
        int pad = Theme.dp(this, 12);
        card.setPadding(pad, pad, pad, pad);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Theme.cr(this, R.color.surface));
        bg.setCornerRadius(Theme.dp(this, 12));
        card.setBackground(bg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Theme.dp(this, 8);
        history.addView(card, 0, lp);
    }
}
