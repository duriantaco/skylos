using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

public class ImportController : Controller
{
    public object Restore()
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(Request.Body);
    }
}
