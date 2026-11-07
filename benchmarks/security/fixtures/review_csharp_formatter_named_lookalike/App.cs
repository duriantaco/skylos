using Microsoft.AspNetCore.Mvc;
public sealed class BinaryFormatter {
    public object Deserialize(object input) { return new object(); }
}
public class ImportController : ControllerBase {
    public object Load() {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(Request.Body); // sink
    }
}
