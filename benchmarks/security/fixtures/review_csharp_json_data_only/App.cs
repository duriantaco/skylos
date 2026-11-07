using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
public class ImportController : ControllerBase {
    public object Load() {
        return JsonSerializer.Deserialize<Order>(Request.Body); // sink
    }
}
public class Order {}
