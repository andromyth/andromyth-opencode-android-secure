package ai.opencode.app;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;

/** Sniffnet-style capture over a local VPN tunnel + wireshark-style
 *  dissection (IP/TCP/UDP/ICMP). Grant the VPN permission, then tap Start.
 *  No root, no raw sockets. Capture is read-only, so normal connectivity
 *  pauses while the tunnel is up. */
public class PacketCaptureActivity extends Activity implements PacketCaptureService.Listener {

    private static final int REQ_VPN = 7501;
    private TextView output;
    private Button toggle;
    private TextView status;
    private final Handler pump = new Handler(Looper.getMainLooper());
    private boolean capturing;
    private final Runnable refresh = new Runnable() {
        @Override public void run() { render(); pump.postDelayed(this, 1000); }
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
        note.setText("VPN-tunnel capture (sniffnet) with IP/TCP/UDP/ICMP dissection "
                + "(wireshark). While capturing, device traffic is captured and dropped, "
                + "so normal connectivity pauses. Grant the VPN permission, then tap Start. "
                + "No root, no raw sockets.");
        note.setTextSize(12);
        note.setTextColor(Theme.TXT_DIM);
        root.addView(note);

        toggle = action(root, capturing ? "Stop capture" : "Start capture", v -> startStop());
        action(root, "Clear", v -> clear());
        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(Theme.TXT_FAINT);
        root.addView(status);

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
    }

    @Override public void onPacket(Packet p) { pump.post(this::render); }

    private void render() {
        List<Packet> list = PacketCaptureService.snapshot();
        StringBuilder b = new StringBuilder();
        b.append("packets: ").append(list.size());
        int tcp = 0, udp = 0, icmp = 0, other = 0;
        for (Packet p : list) {
            switch (p.proto) {
                case "TCP": tcp++; break;
                case "UDP": udp++; break;
                case "ICMP": icmp++; break;
                default: other++; break;
            }
        }
        b.append("   TCP ").append(tcp).append("  UDP ").append(udp)
           .append("  ICMP ").append(icmp).append("  other ").append(other);
        b.append("\n\n");
        int show = Math.min(list.size(), 200);
        for (int i = list.size() - show; i < list.size(); i++) {
            Packet p = list.get(i);
            b.append(ago(p.timeMs)).append("  ").append(p.summary).append("\n");
        }
        output.setText(b.toString());
    }

    private String ago(long t) {
        long ms = System.currentTimeMillis() - t;
        if (ms < 1000) return String.format("+%.1fs", ms / 1000.0);
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
