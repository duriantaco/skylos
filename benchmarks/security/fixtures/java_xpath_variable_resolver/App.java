import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

class App {
  Object lookup(HttpServletRequest request) throws Exception {
    String user = request.getParameter("user");
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.setXPathVariableResolver((QName name) -> user);
    return xpath.evaluate("//account[name/text()=$user]", new org.xml.sax.InputSource("accounts.xml"));
  }
}
