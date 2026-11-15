import java.io.IOException;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

@Controller
class App {
  @GetMapping("/hello")
  void hello(@RequestParam String name, HttpServletResponse response) throws IOException {
    response.setContentType("text/html");
    response.getWriter().write("<h1>" + HtmlUtils.htmlEscape(name) + "</h1>");
  }
}
