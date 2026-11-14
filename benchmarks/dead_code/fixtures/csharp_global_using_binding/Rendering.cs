namespace Probe.Rendering;

static class Casing
{
    public static string Upper(string value)
    {
        return value.ToUpperInvariant();
    }
}

static class OrphanCasing
{
    public static string Lower(string value)
    {
        return value.ToLowerInvariant();
    }
}
