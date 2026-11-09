package ai.opencode.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Sniffnet-style capture over a local VPN tunnel + wireshark-style
 *  dissection (IPv4/IPv6, TCP/UDP/ICMP, app protocol hint). Grant the VPN
 *  permission, then tap Start. No root, no raw sockets. Capture is
 *  read-only, so normal connectivity pauses while the tunnel is up.
 *
 *  <p>Adds the two things the first cut lacked: piggyback statistics
 *  (bytes, protocol mix, top talkers — Sniffnet) and a pcap export that the
 *  friendly Wireshark open-with flow can consume. */
public class PacketCaptureActivity extends Activity implements PacketCaptureService.Listener {

    private static final int REQ_VPN = 7501;

    private TextView output;
    private Button toggle;
    private TextView status;
    private final Handler pump = new Handler(Looper.getMainLooper());
    private boolean capturing;
    private String filter = "ALL";
    private final Map<String, TextView> chips = new HashMap<>();

    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            render();
            if (capturing) pump.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Theme.window(this);
        capturing = PacketCaptureService.isRunning();

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Theme.cr(this, R.color.bg));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = Theme.dp(this, 16);
        root.setPadding(pad, pad, pad, Theme.dp(this, 32));
        scroll.addView(root);
        setContentView(scroll);

        TextView title = new TextView(this);
        title.setText("Packet capture");
        title.setTextSize(23);
        title.setTextColor(Theme.TXT);
        root.addView(title);

        TextView note = new TextView(this);
        note.setText("OpenCode-only VPN capture with IPv4/IPv6, DNS names, HTTP Host, "
                + "visible TLS SNI and best-effort Android app attribution. Other apps "
                + "bypass this VPN and keep normal connectivity; OpenCode external "
                + "network flows are captured but not forwarded while capture is active. "
                + "TLS payloads are not decrypted. PCAP files are saved in app storage "
                + "and can be shared with Wireshark.");
        note.setTextSize(12);
        note.setTextColor(Theme.TXT_DIM);
        root.addView(note);

        toggle = action(root, capturing ? "Stop capture" : "Start capture", v -> startStop());
        action(root, "Export .pcap (open in Wireshark)", v -> exportPcap());
        action(root, "Clear", v -> clear());

        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(Theme.TXT_FAINT);
        root.addView(status);

        root.addView(filterRow());

        output = new TextView(this);
        output.setTextSize(11);
        output.setTextColor(Theme.OK);
        output.setTypeface(android.graphics.Typeface.MONOSPACE);
        output.setPadding(0, Theme.dp(this, 10), 0, 0);
        root.addView(output);

        PacketCaptureService.listener = this;
        if (capturing) status.setText("Capturing…");
        render();
    }

    @Override protected void onResume() {
        super.onResume();
        pump.removeCallbacks(refresh);
        pump.post(refresh);
        render();
    }

    @Override protected void onPause() {
        pump.removeCallbacks(refresh);
        super.onPause();
    }

    @Override protected void onDestroy() {
        PacketCaptureService.listener = null;
        super.onDestroy();
    }

    private View filterRow() {
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.setHorizontalScrollBarEnabled(false);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        hs.addView(row);
        addChip(row, "ALL", "All");
        addChip(row, "TCP", "TCP");
        addChip(row, "UDP", "UDP");
        addChip(row, "ICMP", "ICMP");
        addChip(row, "APP", "App (TLS/DNS…)");
        return hs;
    }

    private void addChip(LinearLayout row, String id, String label) {
        TextView v = new TextView(this);
        v.setText(label);
        v.setTextSize(12);
        v.setTextColor(Theme.TXT);
        v.setPadding(Theme.dp(this, 12), Theme.dp(this, 7),
                Theme.dp(this, 12), Theme.dp(this, 7));
        v.setBackground(Theme.badge(this, Theme.STROKE));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Theme.dp(this, 8);
        lp.topMargin = Theme.dp(this, 10);
        v.setLayoutParams(lp);
        Theme.press(v);
        v.setOnClickListener(x -> { filter = id; render(); });
        chips.put(id, v);
        row.addView(v);
    }

    private void startStop() {
        if (!capturing) {
            Intent prep = VpnService.prepare(this);
            if (prep != null) { startActivityForResult(prep, REQ_VPN); return; }
            startCapture();
        } else {
            stopCapture();
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) startCapture();
            else status.setText("VPN permission denied — capture unavailable");
        }
    }

    private void startCapture() {
        capturing = true;
        PacketCaptureService.clear();
        toggle.setText("Stop capture");
        status.setText("Capturing…");
        startService(new Intent(this, PacketCaptureService.class)
                .setAction(PacketCaptureService.ACTION_START));
        pump.removeCallbacks(refresh);
        pump.post(refresh);
    }

    private void stopCapture() {
        capturing = false;
        toggle.setText("Start capture");
        status.setText("Stopped · " + PacketCaptureService.count() + " packets");
        startService(new Intent(this, PacketCaptureService.class)
                .setAction(PacketCaptureService.ACTION_STOP));
    }

    private void clear() {
        PacketCaptureService.clear();
        output.setText("");
        render();
    }

    private void exportPcap() {
        try {
            File f = PacketCaptureService.exportPcap(this);
            Uri uri = FileProvider.uriFor(f);
            Intent send = new Intent(Intent.ACTION_SEND)
                    .setType("application/vnd.tcpdump.pcap");
            send.putExtra(Intent.EXTRA_STREAM, uri);
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            status.setText("pcap: " + f.getAbsolutePath());
            startActivity(Intent.createChooser(send, "Open capture in Wireshark"));
        } catch (Exception e) {
            status.setText("pcap export failed: " + e);
        }
    }

    /** The refresh pump renders on its own cadence; per-packet callbacks are
     *  intentionally ignored so a busy link cannot flood the UI thread. */
    @Override public void onPacket(Packet p) {}

    private boolean matches(Packet p) {
        switch (filter) {
            case "TCP": return "TCP".equals(p.proto);
            case "UDP": return "UDP".equals(p.proto);
            case "ICMP": return p.proto.startsWith("ICMP");
            case "APP": return !p.appProto.isEmpty() && !"ICMP".equals(p.appProto);
            default: return true;
        }
    }

    private void render() {
        List<Packet> list = PacketCaptureService.snapshot();
        StringBuilder b = new StringBuilder();

        long bytes = 0;
        int tcp = 0, udp = 0, icmp = 0, other = 0;
        Map<String, Integer> apps = new HashMap<>();
        Map<String, long[]> hosts = new HashMap<>();   // ip -> {packets, bytes}
        for (Packet p : list) {
            bytes += p.length;
            switch (p.proto) {
                case "TCP": tcp++; break;
                case "UDP": udp++; break;
                case "ICMP": case "ICMPv6": icmp++; break;
                default: other++; break;
            }
            if (!p.appProto.isEmpty()) {
                Integer c = apps.get(p.appProto);
                apps.put(p.appProto, c == null ? 1 : c + 1);
            }
            String host = p.dstIp;
            if (host != null) {
                long[] v = hosts.get(host);
                if (v == null) { v = new long[2]; hosts.put(host, v); }
                v[0]++;
                v[1] += p.length;
            }
        }

        b.append("packets: ").append(list.size())
         .append("   bytes: ").append(human(bytes))
         .append("\nTCP ").append(tcp).append("  UDP ").append(udp)
         .append("  ICMP ").append(icmp).append("  other ").append(other);
        if (!apps.isEmpty()) b.append("\napps: ").append(topApps(apps));
        String top = topHosts(hosts);
        if (!top.isEmpty()) b.append("\ntop destinations: ").append(top);
        if (PacketCaptureService.lastError != null)
            b.append("\nlast error: ").append(PacketCaptureService.lastError);
        b.append("\n\n");

        int shown = 0;
        for (int i = list.size() - 1; i >= 0 && shown < 200; i--) {
            Packet p = list.get(i);
            if (!matches(p)) continue;
            b.append(ago(p.timeMs)).append("  ").append(p.summary);
            if (!p.ownerPackages.isEmpty()) b.append("  app=").append(p.ownerPackages);
            else if (p.ownerUid >= 0) b.append("  uid=").append(p.ownerUid);
            b.append("\n");
            shown++;
        }
        if (shown == 0 && !list.isEmpty()) b.append("(no packets match the “")
                .append(filter).append("” filter)\n");
        output.setText(b.toString());
        for (Map.Entry<String, TextView> e : chips.entrySet()) {
            boolean on = e.getKey().equals(filter);
            e.getValue().setTextColor(on ? Theme.ACCENT : Theme.TXT);
            e.getValue().setBackground(Theme.badge(this, on ? Theme.ACCENT : Theme.STROKE));
        }
    }

    private String topApps(Map<String, Integer> apps) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(apps.entrySet());
        entries.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < entries.size() && i < 6; i++) {
            Map.Entry<String, Integer> e = entries.get(i);
            if (s.length() > 0) s.append(" · ");
            s.append(e.getKey()).append(' ').append(e.getValue());
        }
        return s.toString();
    }

    private String topHosts(Map<String, long[]> hosts) {
        List<Map.Entry<String, long[]>> entries = new ArrayList<>(hosts.entrySet());
        entries.sort((a, b) -> Long.compare(b.getValue()[1], a.getValue()[1]));
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < entries.size() && i < 5; i++) {
            Map.Entry<String, long[]> e = entries.get(i);
            if (s.length() > 0) s.append("  ");
            s.append(e.getKey()).append(" (").append(e.getValue()[0])
             .append(", ").append(human(e.getValue()[1])).append(")");
        }
        return s.toString();
    }

    private static String human(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", n / 1024.0);
        return String.format(java.util.Locale.US, "%.1f MB", n / (1024.0 * 1024.0));
    }

    private String ago(long t) {
        long ms = System.currentTimeMillis() - t;
        if (ms < 1000) return String.format(java.util.Locale.US, "+%.1fs", ms / 1000.0);
        return "+" + (ms / 1000) + "s";
    }

    private Button action(LinearLayout root, String label, View.OnClickListener l) {
        Button v = new Button(this);
        v.setText(label);
        v.setOnClickListener(l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Theme.dp(this, 10);
        v.setLayoutParams(lp);
        Theme.press(v);
        return v;
    }
}
