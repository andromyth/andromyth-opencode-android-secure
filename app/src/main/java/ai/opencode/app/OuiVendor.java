package ai.opencode.app;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Tiny offline IEEE OUI → vendor map for the handful of prefixes that show
 * up on a home/office LAN. Only used when a MAC address is available (a
 * best-effort /proc/net/arp read, or a future privileged source); no network
 * lookup is ever made.
 */
public final class OuiVendor {

    private OuiVendor() {}

    private static final Map<String, String> MAP = new HashMap<>();

    private static void put(String prefix, String vendor) {
        MAP.put(prefix, vendor);
    }

    static {
        // Phones / tablets / computers
        put("000393", "Apple");
        put("001b63", "Apple");
        put("3c22fb", "Apple");
        put("f01898", "Apple");
        put("a483e7", "Apple");
        put("d0817a", "Apple");
        put("001599", "Samsung");
        put("342387", "Samsung");
        put("5c0a5b", "Samsung");
        put("8c7712", "Samsung");
        put("e8508b", "Samsung");
        put("3c5ab4", "Google");
        put("94eb2c", "Google");
        put("f4f5d8", "Google");
        put("640980", "Xiaomi");
        put("7811dc", "Xiaomi");
        put("f8a45f", "Xiaomi");
        put("001b21", "Intel");
        put("3c970e", "Intel");
        put("00e0fc", "Huawei");
        put("4846fb", "Huawei");
        put("001422", "Dell");
        put("b82a72", "Dell");
        put("001b78", "HP");
        put("9cb654", "HP");
        put("0012fe", "Lenovo");
        put("00155d", "Microsoft");
        put("7c1e52", "Microsoft");

        // Network gear / SBC / IoT
        put("50c7bf", "TP-Link");
        put("a42bb0", "TP-Link");
        put("ec086b", "TP-Link");
        put("00146c", "Netgear");
        put("2c3033", "Netgear");
        put("00000c", "Cisco");
        put("001aa1", "Cisco");
        put("000e4c", "Realtek");
        put("b827eb", "Raspberry Pi");
        put("dca632", "Raspberry Pi");
        put("e45f01", "Raspberry Pi");
        put("240ac4", "Espressif");
        put("3c71bf", "Espressif");
        put("84cca8", "Espressif");
        put("001018", "Broadcom");
        put("00a0c6", "Qualcomm");
        put("001237", "Texas Instruments");

        // TV / media
        put("0013a9", "Sony");
        put("fc0fe6", "Sony");
        put("001c62", "LG");
        put("2c54cf", "LG");
        put("b0a737", "Roku");
        put("d83134", "Roku");
        put("44650d", "Amazon");
        put("74c246", "Amazon");
        put("f0272d", "Amazon");
    }

    /** Vendor for a MAC ("aa:bb:cc:dd:ee:ff" or "aa-bb-..."), or null. */
    public static String vendor(String mac) {
        if (mac == null) return null;
        String h = mac.replace(":", "").replace("-", "")
                .replace(".", "").trim().toLowerCase(Locale.US);
        if (h.length() < 6) return null;
        return MAP.get(h.substring(0, 6));
    }
}
