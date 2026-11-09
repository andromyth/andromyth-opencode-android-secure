package ai.opencode.app;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

/** Android-native Wi-Fi, DNS and mDNS diagnostics; no root or raw sockets required. */
public final class NetworkDiagnosticsActivity extends Activity {
    private static final int REQ_LOCATION = 7401;
    private static final String[] MDNS_TYPES = {
            "_adb-tls-pairing._tcp.", "_adb._tcp.", "_googlecast._tcp.",
            "_ipp._tcp.", "_printer._tcp."
    };

    private TextView output;
    private WifiManager wifi;
    private NsdManager nsd;
    private ConnectivityManager connectivity;
    private BroadcastReceiver scanReceiver;
    private final java.util.List<NsdManager.DiscoveryListener> discoveries =
            new java.util.ArrayList<>();
    private final StringBuilder report = new StringBuilder();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        wifi = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        nsd = (NsdManager) getSystemService(NSD_SERVICE);
        connectivity = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Theme.cr(this, R.color.bg));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = Theme.dp(this, 16);
        root.setPadding(pad, pad, pad, Theme.dp(this, 32));
        scroll.addView(root);
        setContentView(scroll);
        Theme.window(this);

        TextView title = new TextView(this);
        title.setText("Network & LAN diagnostics");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView note = new TextView(this);
        note.setText("Android-native checks. No packet capture, host scanning, route changes or privilege escalation.");
        note.setTextSize(12);
        note.setTextColor(Theme.TXT_DIM);
        root.addView(note);

        root.addView(action("Refresh network / DNS", v -> refreshNetwork()));
        root.addView(action("Scan nearby Wi-Fi", v -> startWifiScan()));
        root.addView(action("Discover LAN services (mDNS)", v -> discoverMdns()));
        root.addView(action("Stop mDNS discovery", v -> stopDiscovery()));

        output = new TextView(this);
        output.setTextSize(12);
        output.setTextColor(Theme.TXT);
        output.setTypeface(android.graphics.Typeface.MONOSPACE);
        output.setPadding(0, Theme.dp(this, 16), 0, 0);
        root.addView(output);
        refreshNetwork();
        registerScanReceiver();
    }

    private TextView action(String label, View.OnClickListener listener) {
        TextView v = new TextView(this);
        v.setText(label);
        v.setTextSize(14);
        v.setTextColor(Theme.TXT);
        v.setPadding(Theme.dp(this, 14), Theme.dp(this, 13),
                Theme.dp(this, 14), Theme.dp(this, 13));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Theme.cr(this, R.color.card));
        bg.setCornerRadius(Theme.dp(this, 12));
        v.setBackground(bg);
        v.setOnClickListener(listener);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Theme.dp(this, 10);
        v.setLayoutParams(lp);
        return v;
    }

    private void line(String value) {
        report.append(value).append('\n');
        if (output != null) output.setText(report.toString());
    }

    private void refreshNetwork() {
        report.setLength(0);
        line("Android API " + Build.VERSION.SDK_INT);
        try {
            Network active = connectivity == null ? null : connectivity.getActiveNetwork();
            LinkProperties lp = active == null ? null : connectivity.getLinkProperties(active);
            line("Active network: " + (active == null ? "unavailable" : "available"));
            if (lp != null) {
                line("Interface: " + lp.getInterfaceName());
                for (InetAddress dns : lp.getDnsServers()) line("DNS: " + dns.getHostAddress());
                for (android.net.LinkAddress address : lp.getLinkAddresses())
                    line("Address: " + address.getAddress().getHostAddress()
                            + "/" + address.getPrefixLength());
            } else {
                line("DNS / link properties: unavailable");
            }
        } catch (SecurityException e) {
            line("Network state permission denied: " + e.getMessage());
        }
        line("");
        line("Interfaces:");
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                StringBuilder addresses = new StringBuilder();
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (addresses.length() > 0) addresses.append(", ");
                    addresses.append(a.getHostAddress());
                }
                line("  " + ni.getName() + (ni.isUp() ? " UP" : " DOWN")
                        + (addresses.length() == 0 ? "" : " · " + addresses));
            }
        } catch (Exception e) {
            line("  unavailable: " + e.getMessage());
        }
        line("");
        line("Wi-Fi scan: " + (hasLocationPermission()
                ? "permission granted (scan still subject to Android throttling/location switch)"
                : "location permission required"));
        line("Raw sockets / CAP_NET_RAW: not granted by this Android API bridge");
        line("CAP_NET_ADMIN / monitor mode: privileged-only");
    }

    private boolean hasLocationPermission() {
        return Build.VERSION.SDK_INT < 23 || checkSelfPermission(
                Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    private void startWifiScan() {
        if (!hasLocationPermission()) {
            requestPermissions(new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, REQ_LOCATION);
            return;
        }
        if (wifi == null) {
            line("Wi-Fi service unavailable");
            return;
        }
        boolean started;
        try {
            started = wifi.startScan();
        } catch (SecurityException e) {
            line("Wi-Fi scan blocked: " + e.getMessage());
            return;
        }
        if (!started) {
            line("Wi-Fi scan request throttled or rejected by Android; showing latest cached results");
            showWifiResults();
        } else {
            line("Wi-Fi scan requested; waiting for Android scan-results broadcast");
        }
    }

    private void registerScanReceiver() {
        scanReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                if (WifiManager.SCAN_RESULTS_AVAILABLE_ACTION.equals(intent.getAction()))
                    showWifiResults();
            }
        };
        IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(scanReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(scanReceiver, filter);
        }
    }

    private void showWifiResults() {
        if (wifi == null || !hasLocationPermission()) return;
        try {
            List<ScanResult> results = wifi.getScanResults();
            line("Nearby access points: " + results.size()
                    + " (Android may return cached/throttled results)");
            for (ScanResult r : results) {
                line("  " + r.SSID + " · " + r.BSSID + " · " + r.frequency
                        + " MHz · " + r.level + " dBm");
            }
        } catch (SecurityException e) {
            line("Wi-Fi results blocked: " + e.getMessage());
        }
    }

    private void discoverMdns() {
        if (nsd == null) {
            line("NsdManager unavailable");
            return;
        }
        for (String type : MDNS_TYPES) {
            NsdManager.DiscoveryListener listener = new NsdManager.DiscoveryListener() {
                @Override public void onDiscoveryStarted(String serviceType) {
                    line("mDNS discovery started: " + serviceType);
                }
                @Override public void onServiceFound(NsdServiceInfo service) {
                    line("mDNS found: " + service.getServiceName() + " · " + service.getServiceType());
                }
                @Override public void onServiceLost(NsdServiceInfo service) {
                    line("mDNS lost: " + service.getServiceName());
                }
                @Override public void onDiscoveryStopped(String serviceType) {
                    line("mDNS stopped: " + serviceType);
                }
                @Override public void onStartDiscoveryFailed(String serviceType, int errorCode) {
                    line("mDNS start failed: " + serviceType + " · " + errorCode);
                    try { nsd.stopServiceDiscovery(this); } catch (Exception ignored) {}
                }
                @Override public void onStopDiscoveryFailed(String serviceType, int errorCode) {
                    line("mDNS stop failed: " + serviceType + " · " + errorCode);
                    try { nsd.stopServiceDiscovery(this); } catch (Exception ignored) {}
                }
            };
            try {
                nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listener);
                discoveries.add(listener);
            } catch (Exception e) {
                line("mDNS unavailable for " + type + ": " + e.getMessage());
            }
        }
    }

    private void stopDiscovery() {
        if (nsd == null) return;
        for (NsdManager.DiscoveryListener listener :
                new java.util.ArrayList<>(discoveries)) {
            try { nsd.stopServiceDiscovery(listener); } catch (Exception ignored) {}
        }
        discoveries.clear();
    }

    @Override public void onRequestPermissionsResult(int requestCode,
            String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_LOCATION) {
            if (hasLocationPermission()) startWifiScan();
            else line("Wi-Fi scan not run: location permission denied");
        }
    }

    @Override protected void onDestroy() {
        stopDiscovery();
        if (scanReceiver != null) {
            try { unregisterReceiver(scanReceiver); } catch (Exception ignored) {}
            scanReceiver = null;
        }
        super.onDestroy();
    }
}
