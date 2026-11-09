using System.IO;
using Microsoft.AspNetCore.Mvc;

public class FilesController : Controller
{
    public string Read(string path)
    {
        return System.IO.File.ReadAllText(path);
    }
}
