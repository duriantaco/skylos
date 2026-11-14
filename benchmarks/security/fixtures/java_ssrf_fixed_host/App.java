import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
class App {
  private final RestTemplate restTemplate = new RestTemplate();

  @GetMapping("/profile")
  String profile(@RequestParam String id) {
    return restTemplate.getForObject("https://api.example.com/users/" + id, String.class);
  }
}
