import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;

class App {
  Object lookup(HttpServletRequest request, DirContext directory, XPath xpath) throws Exception {
    String user = request.getParameter("user");
    String filter = "(&(objectClass=person)(uid=" + user + "))";
    directory.search("ou=people,dc=example,dc=com", filter, null);

    String node = request.getParameter("node");
    String expr = "//account[name/text()='" + node + "']";
    return xpath.evaluate(expr, new org.xml.sax.InputSource());
  }
}
