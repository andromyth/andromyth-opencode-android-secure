package ai.opencode.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Sniffnet-style capture: a local VPN tunnel so every IP packet crossing
 *  the device can be dissected. No root, no raw sockets — the user grants
 *  the VPN permission when the activity starts the tunnel.
 *
 *  <p>Capture is read-only: packets read from the tunnel are dissected and
 *  dropped, not forwarded. While capturing, normal device connectivity is
 *  therefore paused (the tunnel would otherwise tunnel every flow). This is
 *  the deliberate, non-root trade-off for a diagnostics sniffer.
 *
 *  <p>Two things used to stop this from working at all:
 *  <ul>
 *   <li>{@link Builder#establish()} can return {@code null} when the VPN
 *       permission was revoked; the old code dereferenced it on the worker
 *       thread and died.</li>
 *   <li>the tun descriptor delivers <b>raw IP</b> packets, not Ethernet
 *       frames — {@link PacketParser} now handles both.</li>
 *  </ul>
 *  The service also runs in the foreground so the OS does not kill the
 *  capture while the screen is off, and it can export a Wireshark pcap. */
public class PacketCaptureService extends VpnService {

    public static final String ACTION_START = "ai.opencode.app.action.START_CAPTURE";
    public static final String ACTION_STOP = "ai.opencode.app.action.STOP_CAPTURE";

    private static final int MAX_PACKETS = 4000;
    private static final String CHANNEL_ID = "oc-packet-capture";
    private static final int NOTIFICATION_ID = 7501;

    public interface Listener { void onPacket(Packet p); }
    public static volatile Listener listener;
    private static volatile Handler uiHandler;
    /** Last failure reason, surfaced by the activity ("VPN permission denied"…). */
    public static volatile String lastError;
    public static volatile String lastSavedCapturePath;

    private static final List<Packet> packets =
            Collections.synchronizedList(new ArrayList<>());

    public static List<Packet> snapshot() {
        synchronized (packets) { return new ArrayList<>(packets); }
    }

    public static int count() { synchronized (packets) { return packets.size(); } }

    public static void clear() { synchronized (packets) { packets.clear(); } }

    /** Write the current capture to a pcap file openable in Wireshark. */
    public static File exportPcap(Context c) throws IOException {
        File dir = new File(c.getFilesDir(), "captures");
        File saved = PcapWriter.writeToDir(dir, captureFileName(), snapshot());
        lastSavedCapturePath = saved.getAbsolutePath();
        return saved;
    }

    private static volatile boolean running;
    private volatile ParcelFileDescriptor vpnFd;
    private HandlerThread worker;

    public static boolean isRunning() { return running; }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String action = intent.getAction();
        if (ACTION_START.equals(action)) {
            startCapture();
        } else if (ACTION_STOP.equals(action)) {
            stopCapture();
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    @Override public void onDestroy() { stopCapture(); }

    /** VpnService contract: the system or user revoked the tunnel. */
    @Override public void onRevoke() {
        stopCapture();
        super.onRevoke();
    }

    private void startCapture() {
        if (running) return;
        running = true;
        lastError = null;
        uiHandler = new Handler(Looper.getMainLooper());

        // Keep the capture alive while the screen is off / app backgrounded.
        try { startForeground(NOTIFICATION_ID, notification()); } catch (Exception ignored) {}

        HandlerThread workerThread = new HandlerThread("oc-pcap");
        try {
            // VpnService.Builder() takes no context and establish() lives on
            // the builder; both must run after the VPN consent was granted.
            Builder b = new Builder();
            b.setSession("OpenCode packet capture");
            b.setMtu(1500);
            b.addAddress("10.254.254.1", 24);
            b.addRoute("0.0.0.0", 0);
            // Capture IPv6 too (modern networks are IPv6-heavy); read-only.
            b.addAddress("fd00:1:fd00:1::1", 64);
            b.addRoute("::", 0);
            // Safety boundary: do not route every app into this read-only VPN.
            // Only OpenCode is captured; other apps retain their normal network.
            b.addAllowedApplication(getPackageName());
            vpnFd = b.establish();
        } catch (Exception e) {
            lastError = String.valueOf(e);
        }
        if (vpnFd == null) {
            running = false;
            if (lastError == null) lastError = "VPN permission not granted";
            stopSelf();
            return;
        }
        worker = workerThread;
        worker.start();
        new Handler(worker.getLooper()).post(this::runTunnel);
    }

    private void stopCapture() {
        running = false;
        try { if (vpnFd != null) vpnFd.close(); } catch (Exception ignored) {}
        vpnFd = null;
        if (worker != null) { worker.quitSafely(); worker = null; }
    }

    private void runTunnel() {
        ParcelFileDescriptor fd = vpnFd;
        if (fd == null) { running = false; return; }
        FileInputStream in = new FileInputStream(fd.getFileDescriptor());
        byte[] buf = new byte[65536];
        try {
            while (running) {
                int n;
                try { n = in.read(buf); } catch (Exception e) { break; }
                if (n <= 0) break;
                byte[] frame = new byte[n];
                System.arraycopy(buf, 0, frame, 0, n);
                Packet p = PacketParser.parse(System.currentTimeMillis(), frame);
                if (p == null) continue;
                p = attributeOwner(p);
                synchronized (packets) {
                    if (packets.size() >= MAX_PACKETS) packets.remove(0);
                    packets.add(p);
                }
                final Listener l = listener;
                if (l != null && uiHandler != null)
                    uiHandler.post(() -> l.onPacket(p));
            }
        } catch (Exception e) {
            lastError = String.valueOf(e);
        } finally {
            try { in.close(); } catch (Exception ignored) {}
            try { if (vpnFd != null) vpnFd.close(); } catch (Exception ignored) {}
            vpnFd = null;
            running = false;
            if (!snapshot().isEmpty()) {
                try {
                    File saved = PcapWriter.writeToDir(new File(getFilesDir(), "captures"),
                            captureFileName(), snapshot());
                    lastSavedCapturePath = saved.getAbsolutePath();
                } catch (IOException e) {
                    lastError = "capture save failed: " + e;
                }
            }
        }
    }

    private static String captureFileName() {
        return "capture-" + new java.text.SimpleDateFormat("yyyyMMdd-HHmmss-SSS",
                java.util.Locale.US).format(new java.util.Date()) + ".pcap";
    }

    /** Best-effort Android socket-owner lookup; unavailable on API 28 and for
     *  fragmented/non-TCP/UDP flows. It never guesses an application. */
    private Packet attributeOwner(Packet packet) {
        if (Build.VERSION.SDK_INT < 29 || packet.srcPort < 0 || packet.dstPort < 0)
            return packet;
        int protocol = "TCP".equals(packet.proto) ? 6
                : "UDP".equals(packet.proto) ? 17 : -1;
        if (protocol < 0) return packet;
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return packet;
            InetSocketAddress src = new InetSocketAddress(
                    InetAddress.getByName(packet.srcIp), packet.srcPort);
            InetSocketAddress dst = new InetSocketAddress(
                    InetAddress.getByName(packet.dstIp), packet.dstPort);
            int uid = cm.getConnectionOwnerUid(protocol, src, dst);
            if (uid < 0) uid = cm.getConnectionOwnerUid(protocol, dst, src);
            if (uid < 0) return packet;
            String[] packages = getPackageManager().getPackagesForUid(uid);
            String names = "";
            if (packages != null) {
                StringBuilder b = new StringBuilder();
                for (String name : packages) {
                    if (b.length() > 0) b.append(',');
                    b.append(name);
                }
                names = b.toString();
            }
            return packet.withOwner(uid, names);
        } catch (Exception ignored) {
            return packet;
        }
    }

    private Notification notification() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "Packet capture", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("VPN-tunnel packet capture");
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, PacketCaptureActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, piFlags);
        Notification.Builder nb = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("OpenCode packet capture")
                .setContentText("Capturing traffic through the local VPN tunnel")
                .setSmallIcon(R.mipmap.ic_launcher)
                .setOngoing(true)
                .setContentIntent(pi);
        return nb.build();
    }
}
