import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class App {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @PostMapping("/load")
  String load(HttpServletRequest request) throws IOException {
    Payload payload = objectMapper.readValue(request.getInputStream(), Payload.class);
    return payload.name;
  }

  static class Payload {
    public String name;
  }
}
