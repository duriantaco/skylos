using System.IO;
using Microsoft.AspNetCore.Mvc;

public class FilesController : Controller
{
    public string Read(string path)
    {
        var name = Path.GetFileName(path);
        return System.IO.File.ReadAllText(Path.Combine("uploads", name));
    }
}
