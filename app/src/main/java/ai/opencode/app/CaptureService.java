package ai.opencode.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CaptureService extends VpnService {

    public static final String ACTION_START = "ai.opencode.app.CAPTURE_START";
    public static final String ACTION_STOP = "ai.opencode.app.CAPTURE_STOP";

    private static final String CH = "capture";
    private static final int NOTIF_ID = 7;
    private static final int MAX_UPSTREAMS = 6;
    private static final int UPSTREAM_TIMEOUT_MS = 1500;

    private static final String[] PUBLIC_DNS4 = {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"
    };
    private static final String[] PUBLIC_DNS6 = {
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:fe::9"
    };

    private static volatile boolean running;
    private static volatile String lastError = "";
    private static volatile long startedAt;

    private ParcelFileDescriptor tun;
    private FileInputStream in;
    private FileOutputStream out;
    private final Object writeLock = new Object();
    private ExecutorService pool;
    private volatile boolean alive;
    private volatile List<InetAddress> upstreams = new ArrayList<>();

    public static boolean running() {
        return running;
    }

    public static String lastError() {
        return lastError;
    }

    public static long startedAt() {
        return startedAt;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(
                CH, "Network capture", NotificationManager.IMPORTANCE_LOW));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopCapture();
            stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(NOTIF_ID, notif("starting…"));
        if (running) stopCapture();
        if (!startCapture()) {
            stopForeground(true);
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        stopCapture();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopCapture();
        super.onDestroy();
    }

    private boolean startCapture() {
        if (running) return true;
        lastError = "";
        upstreams = collectUpstreams();
        Builder b = new Builder();
        b.setSession("opencode capture");
        b.setMtu(4096);
        b.addAddress(TunDns.DNS4, 32);
        b.addAddress(TunDns.DNS6, 128);
        b.addDnsServer(TunDns.DNS4);
        b.addDnsServer(TunDns.DNS6);
        b.setBlocking(true);
        try {
            Intent cfg = new Intent(this, CaptureActivity.class);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, cfg,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
        } catch (Throwable ignored) {}
        try {
            tun = b.establish();
        } catch (Throwable t) {
            lastError = "could not establish VPN: " + t;
            Trail.record(this, "capture", t);
            return false;
        }
        if (tun == null) {
            lastError = "VPN consent was not granted";
            return false;
        }
        try {
            in = new FileInputStream(tun.getFileDescriptor());
            out = new FileOutputStream(tun.getFileDescriptor());
        } catch (Throwable t) {
            lastError = "could not open tunnel: " + t;
            closeQuietly();
            return false;
        }
        pool = Executors.newFixedThreadPool(4);
        alive = true;
        running = true;
        startedAt = System.currentTimeMillis();
        CaptureStore.start();
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                readLoop();
            }
        }, "oc-capture");
        t.setDaemon(true);
        t.start();
        return true;
    }

    private void stopCapture() {
        alive = false;
        running = false;
        closeQuietly();
        ExecutorService p = pool;
        pool = null;
        if (p != null) p.shutdownNow();
        CaptureStore.stop();
    }

    private void closeQuietly() {
        ParcelFileDescriptor t = tun;
        tun = null;
        FileInputStream i = in;
        in = null;
        FileOutputStream o = out;
        out = null;
        try { if (t != null) t.close(); } catch (Throwable ignored) {}
        try { if (i != null) i.close(); } catch (Throwable ignored) {}
        try { if (o != null) o.close(); } catch (Throwable ignored) {}
    }

    private List<InetAddress> collectUpstreams() {
        Set<InetAddress> set = new LinkedHashSet<>();
        try {
            ConnectivityManager cm =
                    (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            Network n = cm == null ? null : cm.getActiveNetwork();
            LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
            if (lp != null) {
                for (InetAddress a : lp.getDnsServers()) {
                    if (a == null || a.isAnyLocalAddress()) continue;
                    String h = a.getHostAddress();
                    if (TunDns.DNS4.equals(h) || TunDns.DNS6.equals(h)) continue;
                    set.add(a);
                }
            }
        } catch (Throwable ignored) {}
        for (String s : PUBLIC_DNS4) addAddress(set, s);
        for (String s : PUBLIC_DNS6) addAddress(set, s);
        List<InetAddress> list = new ArrayList<>(set);
        if (list.size() > MAX_UPSTREAMS) list = new ArrayList<>(list.subList(0, MAX_UPSTREAMS));
        return list;
    }

    private static void addAddress(Set<InetAddress> set, String s) {
        try { set.add(InetAddress.getByName(s)); } catch (Throwable ignored) {}
    }

    private void readLoop() {
        byte[] buf = new byte[65535];
        while (alive) {
            int n;
            try {
                n = in.read(buf);
            } catch (Throwable t) {
                break;
            }
            if (n <= 0) continue;
            int version = (buf[0] >> 4) & 0xf;
            try {
                if (version == 4) handle4(buf, n);
                else if (version == 6) handle6(buf, n);
            } catch (Throwable ignored) {
            }
        }
    }

    private void handle4(byte[] b, int n) {
        int ihl = (b[0] & 0xf) * 4;
        if (ihl < 20 || n < ihl + 8) return;
        if ((b[9] & 0xff) != 17) return;
        int uoff = ihl;
        int sport = TunDns.u16(b, uoff);
        int dport = TunDns.u16(b, uoff + 2);
        if (dport != 53) return;
        int ulen = TunDns.u16(b, uoff + 4);
        if (ulen < 8 || ihl + ulen > n) return;
        int plen = ulen - 8;
        if (plen < 12) return;
        byte[] payload = new byte[plen];
        System.arraycopy(b, uoff + 8, payload, 0, plen);
        TunDns.Q q = TunDns.parseQuestion(payload, 0, plen);
        if (q == null) return;
        CaptureStore.hit(q.name, q.type, System.currentTimeMillis());
        byte[] src = {b[12], b[13], b[14], b[15]};
        submit4(src, sport, payload, q.end);
    }

    private void handle6(byte[] b, int n) {
        if (n < 40 + 8) return;
        if ((b[6] & 0xff) != 17) return;
        int uoff = 40;
        int sport = TunDns.u16(b, uoff);
        int dport = TunDns.u16(b, uoff + 2);
        if (dport != 53) return;
        int ulen = TunDns.u16(b, uoff + 4);
        if (ulen < 8 || 40 + ulen > n) return;
        int plen = ulen - 8;
        if (plen < 12) return;
        byte[] payload = new byte[plen];
        System.arraycopy(b, uoff + 8, payload, 0, plen);
        TunDns.Q q = TunDns.parseQuestion(payload, 0, plen);
        if (q == null) return;
        CaptureStore.hit(q.name, q.type, System.currentTimeMillis());
        byte[] src = new byte[16];
        System.arraycopy(b, 8, src, 0, 16);
        submit6(src, sport, payload, q.end);
    }

    private void submit4(byte[] src, int sport, byte[] payload, int qend) {
        ExecutorService p = pool;
        if (p == null) return;
        try {
            p.execute(new Runnable() {
                @Override public void run() {
                    byte[] resp = resolve(payload, payload.length);
                    if (resp == null) resp = TunDns.dnsError(payload, qend, 2);
                    if (resp != null) write(TunDns.reply4(src, sport, resp));
                }
            });
        } catch (Throwable ignored) {}
    }

    private void submit6(byte[] src, int sport, byte[] payload, int qend) {
        ExecutorService p = pool;
        if (p == null) return;
        try {
            p.execute(new Runnable() {
                @Override public void run() {
                    byte[] resp = resolve(payload, payload.length);
                    if (resp == null) resp = TunDns.dnsError(payload, qend, 2);
                    if (resp != null) write(TunDns.reply6(src, sport, resp));
                }
            });
        } catch (Throwable ignored) {}
    }

    private byte[] resolve(byte[] query, int len) {
        List<InetAddress> ups = upstreams;
        for (InetAddress up : ups) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                protect(s);
                s.setSoTimeout(UPSTREAM_TIMEOUT_MS);
                s.send(new DatagramPacket(query, len, up, 53));
                byte[] rb = new byte[4096];
                DatagramPacket r = new DatagramPacket(rb, rb.length);
                s.receive(r);
                int got = r.getLength();
                if (got < 12) continue;
                if (rb[0] != query[0] || rb[1] != query[1]) continue;
                byte[] outBytes = new byte[got];
                System.arraycopy(rb, 0, outBytes, 0, got);
                return outBytes;
            } catch (Throwable ignored) {
            } finally {
                if (s != null) s.close();
            }
        }
        return null;
    }

    private void write(byte[] packet) {
        FileOutputStream o = out;
        if (o == null) return;
        synchronized (writeLock) {
            try {
                o.write(packet);
                o.flush();
            } catch (Throwable ignored) {}
        }
    }

    private Notification notif(String text) {
        Intent open = new Intent(this, CaptureActivity.class);
        PendingIntent pOpen = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Intent stop = new Intent(this, CaptureService.class).setAction(ACTION_STOP);
        PendingIntent pStop = PendingIntent.getService(this, 1, stop,
                PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CH)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("Network capture")
                .setContentText(text)
                .setContentIntent(pOpen)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(null, "Stop", pStop).build())
                .build();
    }
}
