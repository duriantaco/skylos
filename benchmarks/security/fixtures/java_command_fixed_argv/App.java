import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class App {
  @GetMapping("/status")
  String status(@RequestParam String label) throws IOException {
    Process process = Runtime.getRuntime().exec(new String[] {"git", "status", "--short"});
    return label + ":" + process.pid();
  }
}
