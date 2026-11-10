package ai.opencode.app;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Offline ARP security lab. Every observation is synthetic and handled in memory.
 * This screen never reads or changes the device/network ARP table.
 */
public final class ArpSecurityLabActivity extends Activity {
    private LinearLayout history;
    private TextView status;
    private int runCount;

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
        title.setText("ARP security lab");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView boundary = new TextView(this);
        boundary.setText("OFFLINE SIMULATION ONLY\nSynthetic IP/MAC observations are generated in memory. Nothing is sent to Wi-Fi or LAN devices. This lab does not inspect the device ARP cache, open packet sockets, alter routes, or enable forwarding. Results below are demonstrations, not findings about your current network.");
        boundary.setTextSize(12);
        boundary.setTextColor(Theme.TXT_DIM);
        boundary.setPadding(0, Theme.dp(this, 8), 0, Theme.dp(this, 10));
        root.addView(boundary);

        status = new TextView(this);
        status.setText("No scenarios run yet.");
        status.setTextSize(13);
        status.setTextColor(Theme.TXT);
        root.addView(status);

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
        historyTitle.setText("Simulation history");
        historyTitle.setTextSize(18);
        historyTitle.setTextColor(Theme.TXT);
        historyTitle.setPadding(0, Theme.dp(this, 20), 0, Theme.dp(this, 4));
        root.addView(historyTitle);

        history = new LinearLayout(this);
        history.setOrientation(LinearLayout.VERTICAL);
        root.addView(history);
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
