import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import javax.servlet.http.HttpServletRequest;

class App {
  String fetch(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URI uri = URI.create(target);
    HttpRequest outbound = HttpRequest.newBuilder().uri(uri).GET().build();
    return HttpClient.newHttpClient()
        .send(outbound, java.net.http.HttpResponse.BodyHandlers.ofString())
        .body();
  }
}
