using System.Linq;
using System.Reflection;

namespace Probe.Reflection;

static class SurrogateMethods
{
    internal static string[] Names()
    {
        return typeof(SurrogateMethods).GetTypeInfo().DeclaredMethods.Select(m => m.Name).ToArray();
    }

    internal static int Alpha(int value)
    {
        return value;
    }

    internal static int Beta(int value)
    {
        return value + 1;
    }
}

static class PlainMethods
{
    internal static int Gamma(int value)
    {
        return value;
    }

    internal static int OrphanDelta(int value)
    {
        return value + 1;
    }
}

public static class ReflectionEntry
{
    public static int Run()
    {
        return SurrogateMethods.Names().Length + PlainMethods.Gamma(1);
    }
}
