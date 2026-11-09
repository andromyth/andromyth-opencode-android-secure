package ai.opencode.app;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
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
 *  the deliberate, non-root trade-off for a diagnostics sniffer. */
public class PacketCaptureService extends VpnService {

    public static final String ACTION_START = "ai.opencode.app.action.START_CAPTURE";
    public static final String ACTION_STOP = "ai.opencode.app.action.STOP_CAPTURE";

    private static final int MAX_PACKETS = 4000;

    public interface Listener { void onPacket(Packet p); }
    public static volatile Listener listener;
    private static volatile Handler uiHandler;

    private static final List<Packet> packets =
            Collections.synchronizedList(new ArrayList<>());

    public static List<Packet> snapshot() {
        synchronized (packets) { return new ArrayList<>(packets); }
    }

    public static int count() { synchronized (packets) { return packets.size(); } }

    public static void clear() { synchronized (packets) { packets.clear(); } }

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
        uiHandler = new Handler(Looper.getMainLooper());
        HandlerThread workerThread = new HandlerThread("oc-pcap");
        try {
            // VpnService.Builder() takes no context and establish() lives on
            // the builder; both must run on the main thread (onStartCommand).
            Builder b = new Builder();
            b.setSession("OpenCode packet capture");
            b.addAddress("10.254.254.1", 24);
            b.addRoute("0.0.0.0", 0);
            vpnFd = b.establish();
        } catch (Exception e) {
            running = false;
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
        FileInputStream in = new FileInputStream(vpnFd.getFileDescriptor());
        byte[] buf = new byte[65536];
        try {
            while (running) {
                int n;
                try { n = in.read(buf); } catch (Exception e) { break; }
                if (n <= 0) break;
                byte[] frame = new byte[n];
                System.arraycopy(buf, 0, frame, 0, n);
                final Packet p = PacketParser.parse(System.currentTimeMillis(), frame);
                if (p == null) continue;
                synchronized (packets) {
                    if (packets.size() >= MAX_PACKETS) packets.remove(0);
                    packets.add(p);
                }
                final Packet pp = p;
                final Listener l = listener;
                if (l != null && uiHandler != null)
                    uiHandler.post(() -> l.onPacket(pp));
            }
        } catch (Exception ignored) {} finally {
            try { in.close(); } catch (Exception ignored) {}
            try { if (vpnFd != null) vpnFd.close(); } catch (Exception ignored) {}
            vpnFd = null;
            running = false;
        }
    }
}
