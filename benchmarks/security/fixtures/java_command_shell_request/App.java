import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class App {
  @GetMapping("/run")
  String run(@RequestParam String cmd) throws IOException {
    Process process = Runtime.getRuntime().exec(new String[] {"sh", "-c", cmd});
    return String.valueOf(process.pid());
  }
}
