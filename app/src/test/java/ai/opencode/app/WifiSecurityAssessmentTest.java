package ai.opencode.app;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import static org.junit.Assert.*;

public class WifiSecurityAssessmentTest {
    @Test public void identifiesOpenAndWepNetworksAsHighRisk() {
        List<WifiSecurityAssessment.Finding> findings = WifiSecurityAssessment.assess(Arrays.asList(
                new WifiSecurityAssessment.AccessPoint("Cafe", "[ESS]", 2412, -50),
                new WifiSecurityAssessment.AccessPoint("Legacy", "[WEP][ESS]", 5180, -60)));
        assertEquals(2, findings.size());
        assertEquals(WifiSecurityAssessment.Severity.HIGH, findings.get(0).severity);
        assertEquals("Open network", findings.get(0).category);
        assertEquals("WEP", findings.get(1).category);
    }

    @Test public void recognizesWpa3AndWpa2WithoutHighRiskAlert() {
        List<WifiSecurityAssessment.Finding> findings = WifiSecurityAssessment.assess(Arrays.asList(
                new WifiSecurityAssessment.AccessPoint("Modern", "[WPA3-SAE-CCMP][ESS]", 5975, -40),
                new WifiSecurityAssessment.AccessPoint("LegacySecure", "[WPA2-PSK-CCMP][ESS]", 2437, -55)));
        assertEquals("WPA3", findings.get(0).category);
        assertEquals("WPA2", findings.get(1).category);
        assertEquals(WifiSecurityAssessment.Severity.INFO, findings.get(0).severity);
    }

    @Test public void emptyAndNullInputsReturnNoFindings() {
        assertTrue(WifiSecurityAssessment.assess(Collections.<WifiSecurityAssessment.AccessPoint>emptyList()).isEmpty());
        assertTrue(WifiSecurityAssessment.assess(null).isEmpty());
    }

    @Test public void reportsBandBoundaries() {
        assertEquals("2.4 GHz", WifiSecurityAssessment.bandForFrequency(2412));
        assertEquals("5 GHz", WifiSecurityAssessment.bandForFrequency(5180));
        assertEquals("6 GHz", WifiSecurityAssessment.bandForFrequency(5975));
        assertEquals("Unknown band", WifiSecurityAssessment.bandForFrequency(900));
    }

    @Test public void hiddenSsidIsNotNull() {
        String report = WifiSecurityAssessment.report(Collections.singletonList(
                new WifiSecurityAssessment.AccessPoint(null, "[ESS]", 2412, -50)));
        assertTrue(report.contains("(hidden SSID)"));
    }
}
