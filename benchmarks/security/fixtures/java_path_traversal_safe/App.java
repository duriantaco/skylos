import java.nio.file.*;
import javax.servlet.http.HttpServletRequest;

class App {
  String read(HttpServletRequest request) throws Exception {
    String file = request.getParameter("file");
    Path base = Paths.get("/srv/data");
    Path target = base.resolve(file).normalize();
    if (!target.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readString(target);
  }
}
