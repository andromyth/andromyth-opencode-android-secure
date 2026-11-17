package ai.opencode.app;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Android-supported passive LAN configuration monitor with offline ARP simulations.
 * It observes network metadata only; it does not inspect ARP frames or prove spoofing.
 */
public final class ArpSecurityLabActivity extends Activity {
    private LinearLayout history;
    private TextView status;
    private int runCount;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private boolean monitoring;
    private boolean destroyed;
    private String liveBaseline;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        connectivity = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
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
        title.setText("LAN security monitor");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView boundary = new TextView(this);
        boundary.setText("LIVE MODE: Android-supported, read-only network observation. Tracks active network, interface, IP addresses, default gateway and DNS configuration. It does not read /proc/net/arp or capture Ethernet ARP frames, so it cannot confirm ARP spoofing. Configuration changes are investigation warnings, not proof of attack. Offline ARP detector simulations remain available below.");
        boundary.setTextSize(12);
        boundary.setTextColor(Theme.TXT_DIM);
        boundary.setPadding(0, Theme.dp(this, 8), 0, Theme.dp(this, 10));
        root.addView(boundary);

        status = new TextView(this);
        status.setText("No live network snapshot or scenarios yet.");
        status.setTextSize(13);
        status.setTextColor(Theme.TXT);
        root.addView(status);

        root.addView(action("Start live passive monitoring", v -> startLiveMonitoring()));
        root.addView(action("Stop live monitoring", v -> stopLiveMonitoring()));
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
            status.setText("History cleared. Live monitoring state is unchanged.");
        }));

        TextView historyTitle = new TextView(this);
        historyTitle.setText("Live network alerts and simulation history");
        historyTitle.setTextSize(18);
        historyTitle.setTextColor(Theme.TXT);
        historyTitle.setPadding(0, Theme.dp(this, 20), 0, Theme.dp(this, 4));
        root.addView(historyTitle);

        history = new LinearLayout(this);
        history.setOrientation(LinearLayout.VERTICAL);
        root.addView(history);
    }

    private void startLiveMonitoring() {
        if (connectivity == null) {
            showLiveUnavailable("Connectivity service unavailable");
            return;
        }
        if (monitoring) {
            pollLive();
            return;
        }
        monitoring = true;
        liveBaseline = null;
        try {
            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { pollLive(); }
                @Override public void onLost(Network network) { pollLive(); }
                @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                    pollLive();
                }
                @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                    pollLive();
                }
            };
            connectivity.registerDefaultNetworkCallback(networkCallback);
            status.setText("Monitoring active network changes…");
            pollLive();
        } catch (RuntimeException e) {
            monitoring = false;
            unregisterNetworkCallback();
            showLiveUnavailable(e.toString());
        }
    }

    private void stopLiveMonitoring() {
        monitoring = false;
        unregisterNetworkCallback();
        status.setText("Live network monitoring stopped.");
    }

    private void unregisterNetworkCallback() {
        if (networkCallback != null && connectivity != null) {
            try { connectivity.unregisterNetworkCallback(networkCallback); }
            catch (IllegalArgumentException ignored) {}
            networkCallback = null;
        }
    }

    private void pollLive() {
        if (destroyed) return;
        if (connectivity == null) {
            showLiveUnavailable("Connectivity service unavailable");
            return;
        }
        io.execute(() -> {
            try {
                Network network = connectivity.getActiveNetwork();
                if (network == null) {
                    runOnUiThread(() -> applyLiveSnapshot("No active network", "No active network is currently reported by Android."));
                    return;
                }
                LinkProperties properties = connectivity.getLinkProperties(network);
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                StringBuilder detail = new StringBuilder();
                detail.append("Network: ").append(network).append('\n');
                if (capabilities != null) {
                    detail.append("Transport: ");
                    boolean found = false;
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        detail.append("Wi-Fi"); found = true;
                    }
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                        if (found) detail.append(", ");
                        detail.append("cellular"); found = true;
                    }
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                        if (found) detail.append(", ");
                        detail.append("Ethernet"); found = true;
                    }
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        if (found) detail.append(", ");
                        detail.append("VPN"); found = true;
                    }
                    if (!found) detail.append("other / not reported");
                    detail.append('\n');
                } else {
                    detail.append("Transport: unavailable\n");
                }
                if (properties == null) {
                    detail.append("Link properties: unavailable\n");
                } else {
                    detail.append("Interface: ").append(properties.getInterfaceName()).append('\n');
                    for (LinkAddress address : properties.getLinkAddresses())
                        detail.append("Address: ").append(address).append('\n');
                    for (RouteInfo route : properties.getRoutes()) {
                        if (route.isDefaultRoute() && route.getGateway() != null
                                && !route.getGateway().isAnyLocalAddress())
                            detail.append("Default gateway: ")
                                    .append(route.getGateway().getHostAddress()).append('\n');
                    }
                    for (java.net.InetAddress dns : properties.getDnsServers())
                        detail.append("DNS: ").append(dns.getHostAddress()).append('\n');
                }
                String snapshot = detail.toString().trim();
                runOnUiThread(() -> applyLiveSnapshot(snapshot, snapshot));
            } catch (RuntimeException e) {
                runOnUiThread(() -> showLiveUnavailable(e.toString()));
            }
        });
    }

    private void applyLiveSnapshot(String fingerprint, String detail) {
        if (destroyed || isFinishing()) return;
        if (liveBaseline == null) {
            liveBaseline = fingerprint;
            status.setText("LIVE · Baseline captured. Android network metadata is accessible.");
            addLiveCard("LIVE NETWORK BASELINE", detail);
        } else if (!liveBaseline.equals(fingerprint)) {
            liveBaseline = fingerprint;
            status.setText("NETWORK CONFIGURATION CHANGED · Review the new values. This is not proof of spoofing.");
            addLiveCard("NETWORK CHANGE — INVESTIGATE", detail);
        } else {
            status.setText("LIVE · No network configuration change detected since baseline. This does not establish that the LAN is safe.");
        }
    }

    private void showLiveUnavailable(String reason) {
        if (destroyed || isFinishing()) return;
        monitoring = false;
        unregisterNetworkCallback();
        status.setText("LIVE NETWORK MONITOR UNAVAILABLE · " + reason);
        addLiveCard("LIVE NETWORK ACCESS UNAVAILABLE", reason);
    }

    @Override protected void onPause() {
        stopLiveMonitoring();
        super.onPause();
    }

    @Override protected void onDestroy() {
        destroyed = true;
        unregisterNetworkCallback();
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

    private void addLiveCard(String label, String detail) {
        TextView card = new TextView(this);
        card.setText(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date())
                + " · " + label + "\n" + detail
                + "\nAndroid network metadata only; this is not an ARP packet observation.");
        card.setTextSize(12);
        card.setTextColor(Theme.TXT);
        card.setPadding(Theme.dp(this, 12), Theme.dp(this, 12), Theme.dp(this, 12), Theme.dp(this, 12));
        history.addView(card, 0);
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
