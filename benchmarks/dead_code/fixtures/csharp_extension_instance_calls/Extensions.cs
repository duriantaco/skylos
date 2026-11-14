using System.Collections.Generic;

namespace Probe.Ext;

internal static class BuilderExtensions
{
    public static List<string> AddDefaults(this List<string> items)
    {
        items.AddMarker("default");
        return items;
    }

    private static void AddMarker(this List<string> items, string marker)
    {
        items.Add(marker);
    }

    private static void OrphanMarker(this List<string> items, string marker)
    {
        items.Add(marker + "!");
    }

    private static int Pad(string value)
    {
        return value.Length;
    }
}

internal static class OrphanExtensions
{
    public static int CountTwice(this List<string> items)
    {
        return items.Count * 2;
    }
}

public class Padded
{
    public int Pad()
    {
        return 1;
    }
}
