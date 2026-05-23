using System.IO;

public class Files
{
    public string Read(string path)
    {
        return File.ReadAllText(path);
    }
}
