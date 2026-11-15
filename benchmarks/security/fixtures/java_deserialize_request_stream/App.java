import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class App {
  @PostMapping("/load")
  String load(HttpServletRequest request) throws IOException, ClassNotFoundException {
    try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
      return String.valueOf(in.readObject());
    }
  }
}
