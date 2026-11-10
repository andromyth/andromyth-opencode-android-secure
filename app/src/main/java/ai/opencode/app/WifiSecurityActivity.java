package ai.opencode.app;

import android.Manifest;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Passive Android Wi-Fi security assessment and cloud-AI handoff. */
public final class WifiSecurityActivity extends Activity {
    private static final int REQ_WIFI_LOCATION = 7511;
    private WifiManager wifi;
    private LinearLayout root;
    private TextView status, output;
    private BroadcastReceiver receiver;
    private String lastReport = "";
    private boolean receiverRegistered;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        wifi = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Theme.cr(this, R.color.bg));
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = Theme.dp(this, 16);
        root.setPadding(pad, pad, pad, Theme.dp(this, 30));
        scroll.addView(root);
        setContentView(scroll);
        Theme.window(this);

        TextView title = new TextView(this);
        title.setText("Wi-Fi security assessment");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView note = new TextView(this);
        note.setText("Passive only: uses Android-provided Wi-Fi scan metadata. No deauthentication, credential capture, handshake cracking, rogue-AP creation, packet injection, monitor-mode forcing or security-control bypass. Scan results may be cached or throttled by Android.");
        note.setTextSize(12);
        note.setTextColor(Theme.TXT_DIM);
        note.setPadding(0, Theme.dp(this, 8), 0, Theme.dp(this, 12));
        root.addView(note);

        status = new TextView(this);
        status.setTextSize(13);
        status.setTextColor(Theme.TXT);
        root.addView(status);
        root.addView(action("Check Android compatibility", v -> showCompatibility()));
        root.addView(action("Check USB-OTG adapter", v -> showUsbHostDevices()));
        root.addView(action("Scan nearby Wi-Fi (passive)", v -> requestScan()));
        root.addView(action("Analyze findings with cloud AI", v -> askCloudAi()));
        root.addView(action("Copy assessment report", v -> copyReport()));

        output = new TextView(this);
        output.setTextSize(12);
        output.setTextColor(Theme.TXT);
        output.setTypeface(Typeface.MONOSPACE);
        output.setPadding(0, Theme.dp(this, 14), 0, 0);
        root.addView(output);
        showCompatibility();
        registerScanReceiver();
    }

    private TextView action(String label, View.OnClickListener listener) {
        TextView view = new TextView(this);
        view.setText(label);
        view.setTextSize(14);
        view.setTextColor(Theme.TXT);
        view.setPadding(Theme.dp(this, 14), Theme.dp(this, 13),
                Theme.dp(this, 14), Theme.dp(this, 13));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Theme.cr(this, R.color.surface));
        bg.setCornerRadius(Theme.dp(this, 12));
        view.setBackground(bg);
        view.setOnClickListener(listener);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Theme.dp(this, 9);
        view.setLayoutParams(lp);
        return view;
    }

    private void showCompatibility() {
        StringBuilder b = new StringBuilder();
        b.append("Android API ").append(Build.VERSION.SDK_INT).append('\n');
        b.append("Root: ").append(hasRootIndicator()
                ? "possible su/Magisk indicator found (not proof of active root)"
                : "no common root indicator found (not proof of non-root)").append('\n');
        b.append("Wi-Fi service: ").append(wifi == null ? "UNAVAILABLE" : "AVAILABLE").append('\n');
        if (wifi != null) {
            try {
                b.append("Wi-Fi enabled: ").append(wifi.isWifiEnabled()).append('\n');
                b.append("5 GHz support: ").append(wifi.is5GHzBandSupported()).append('\n');
                if (Build.VERSION.SDK_INT >= 30)
                    b.append("6 GHz support: ").append(wifi.is6GHzBandSupported()).append('\n');
                b.append("Scan always available: ").append(wifi.isScanAlwaysAvailable()).append('\n');
            } catch (SecurityException e) {
                b.append("Capability query blocked by Android: ").append(e.getClass().getSimpleName()).append('\n');
            }
        }
        b.append("Monitor mode / raw 802.11 capture: NOT EXPOSED through the public Android Wi-Fi API.\n");
        b.append("Root does not override driver, firmware, SELinux or Android API limitations.\n");
        status.setText(b.toString());
    }

    private void showUsbHostDevices() {
        StringBuilder b = new StringBuilder();
        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_USB_HOST)) {
            b.append("USB host / OTG: NOT REPORTED by Android for this device.\\n");
            b.append("A USB adapter cannot be assessed through the Android USB host API.\\n");
            status.setText(b.toString());
            return;
        }

        UsbManager manager = (UsbManager) getSystemService(Context.USB_SERVICE);
        if (manager == null) {
            status.setText("USB host service: UNAVAILABLE.");
            return;
        }

        java.util.HashMap<String, UsbDevice> devices = manager.getDeviceList();
        b.append("USB host / OTG: AVAILABLE\\n");
        b.append("Attached USB devices: ").append(devices.size()).append('\\n');
        if (devices.isEmpty()) {
            b.append("No USB device is currently enumerated. Check the OTG adapter, cable and power.\\n");
        }
        for (UsbDevice device : devices.values()) {
            b.append("Device VID:PID = 0x")
                    .append(Integer.toHexString(device.getVendorId()))
                    .append(":0x").append(Integer.toHexString(device.getProductId()))
                    .append("; interfaces = ").append(device.getInterfaceCount()).append('\\n');
            for (int i = 0; i < device.getInterfaceCount(); i++) {
                UsbInterface usbInterface = device.getInterface(i);
                b.append("  interface ").append(i)
                        .append(": class=0x").append(Integer.toHexString(usbInterface.getInterfaceClass()))
                        .append(", subclass=0x").append(Integer.toHexString(usbInterface.getInterfaceSubclass()))
                        .append(", protocol=0x").append(Integer.toHexString(usbInterface.getInterfaceProtocol()))
                        .append('\\n');
            }
        }
        b.append("Important: USB enumeration does not prove this is a Wi-Fi adapter, that a kernel driver is loaded, or that monitor mode/raw 802.11 capture is supported.\\n");
        b.append("No USB device is opened and no permission, driver, root or security setting is changed.\\n");
        status.setText(b.toString());
    }

    private boolean hasRootIndicator() {
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk"};
        for (String path : paths) if (new File(path).exists()) return true;
        return false;
    }

    private boolean hasScanPermission() {
        return Build.VERSION.SDK_INT < 23 || checkSelfPermission(
                Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    private void requestScan() {
        if (wifi == null) {
            status.setText("UNAVAILABLE: Android Wi-Fi service is not present.");
            return;
        }
        if (!hasScanPermission()) {
            requestPermissions(new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, REQ_WIFI_LOCATION);
            return;
        }
        try {
            if (!wifi.isWifiEnabled()) {
                status.setText("LIMITED: enable Wi-Fi in Android Settings, then retry. The app will not enable it automatically.");
                return;
            }
            boolean started = wifi.startScan();
            status.setText(started
                    ? "Scan requested. Waiting for Android scan-results broadcast…"
                    : "Android throttled/rejected a new scan; assessing latest cached results.");
            if (!started) showResults();
        } catch (SecurityException e) {
            status.setText("UNAVAILABLE: Android denied Wi-Fi scan access (" + e.getClass().getSimpleName() + ").");
        }
    }

    private void registerScanReceiver() {
        receiver = new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                if (WifiManager.SCAN_RESULTS_AVAILABLE_ACTION.equals(intent.getAction())) showResults();
            }
        };
        IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        if (Build.VERSION.SDK_INT >= 33)
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(receiver, filter);
        receiverRegistered = true;
    }

    private void showResults() {
        if (wifi == null || !hasScanPermission()) return;
        try {
            List<ScanResult> rows = wifi.getScanResults();
            List<WifiSecurityAssessment.AccessPoint> points = new ArrayList<>();
            for (ScanResult row : rows) {
                points.add(new WifiSecurityAssessment.AccessPoint(
                        row.SSID, row.capabilities, row.frequency, row.level));
            }
            lastReport = WifiSecurityAssessment.report(points);
            output.setText(lastReport);
            status.setText("Observed " + rows.size()
                    + " access point(s). Android may provide cached results; findings are indicators, not proof of compromise.");
        } catch (SecurityException e) {
            status.setText("UNAVAILABLE: Android denied scan-result access (" + e.getClass().getSimpleName() + ").");
        }
    }

    private void askCloudAi() {
        if (lastReport.isEmpty()) {
            Toast.makeText(this, "Run a Wi-Fi scan first.", Toast.LENGTH_SHORT).show();
            return;
        }
        String prompt = "Act as a defensive Wi-Fi security analyst. Analyze this Android passive scan report. "
                + "Separate observed facts from hypotheses; do not claim AP identity or compromise from SSID/security metadata alone. "
                + "Prioritize practical defensive remediation. Do not propose attacks, credential capture, deauthentication, cracking, "
                + "or bypassing Android controls.\n\n" + lastReport;
        Intent intent = new Intent(this, ChatActivity.class);
        intent.putExtra("prefillMessage", prompt);
        startActivity(intent);
    }

    private void copyReport() {
        if (lastReport.isEmpty()) {
            Toast.makeText(this, "No assessment report yet.", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("Wi-Fi security assessment", lastReport));
        Toast.makeText(this, "Assessment copied.", Toast.LENGTH_SHORT).show();
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_WIFI_LOCATION) {
            if (hasScanPermission()) requestScan();
            else status.setText("LIMITED: location permission denied; Wi-Fi scan metadata is unavailable.");
        }
    }

    @Override protected void onDestroy() {
        if (receiverRegistered && receiver != null) {
            try { unregisterReceiver(receiver); } catch (Exception ignored) {}
        }
        super.onDestroy();
    }
}
