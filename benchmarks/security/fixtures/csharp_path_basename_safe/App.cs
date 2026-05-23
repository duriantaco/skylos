using System.IO;

public class Files
{
    public string Read(string path)
    {
        var name = Path.GetFileName(path);
        return File.ReadAllText(Path.Combine("uploads", name));
    }
}
