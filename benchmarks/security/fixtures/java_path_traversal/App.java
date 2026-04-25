import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    String file = request.getParameter("file");
    Path target = Paths.get("/srv/data", file);
    return Files.readString(target);
  }
}
