import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class App {
  void redirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    if (!next.startsWith("/")) {
      throw new IllegalArgumentException("bad redirect");
    }
    response.sendRedirect(next);
  }
}
