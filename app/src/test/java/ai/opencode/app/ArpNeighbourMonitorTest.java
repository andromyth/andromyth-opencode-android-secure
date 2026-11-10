package ai.opencode.app;
import static org.junit.Assert.*;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;
public class ArpNeighbourMonitorTest {
 @Test public void changedBindingProducesWarnings() {
  Map<String,String> base=new LinkedHashMap<>(); base.put("192.168.1.1","aa:bb:cc:dd:ee:01");
  ArpSpoofLab.Detector d=new ArpSpoofLab.Detector(base);
  assertEquals(2,d.observe(new ArpSpoofLab.Observation("192.168.1.1","aa:bb:cc:dd:ee:02")).size());
 }
 @Test public void sameBindingIsNotAnAlert() {
  Map<String,String> base=new LinkedHashMap<>(); base.put("192.168.1.1","aa:bb:cc:dd:ee:01");
  assertTrue(new ArpSpoofLab.Detector(base).observe(new ArpSpoofLab.Observation("192.168.1.1","aa:bb:cc:dd:ee:01")).isEmpty());
 }
}
