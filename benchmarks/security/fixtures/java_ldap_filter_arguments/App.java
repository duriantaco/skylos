import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

class App {
  Object lookup(HttpServletRequest request, DirContext directory) throws Exception {
    String user = request.getParameter("user");
    return directory.search(
        "ou=people,dc=example,dc=com",
        "(&(objectClass=person)(uid={0}))",
        new Object[] {user},
        new SearchControls());
  }
}
