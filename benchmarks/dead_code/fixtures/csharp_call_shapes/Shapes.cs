using System;

namespace Probe.Shapes;

public class Binder
{
    public static object Create(string name, Action<object, object> propertyChanged)
    {
        return name + propertyChanged;
    }
}

public class BadgeView
{
    public static readonly object Property = Binder.Create("Text", propertyChanged: OnTextChanged);

    private static void OnTextChanged(object oldValue, object newValue)
    {
    }

    private static void OnOrphanChanged(object oldValue, object newValue)
    {
    }

    public string Render(bool compact)
    {
        var label = compact ? Tag("c") : Tag("full");
        return label;
    }

    private string Tag(string label)
    {
        return "[" + label + "]";
    }

    private string OrphanTag(string label)
    {
        return "<" + label + ">";
    }

    private string Pair(string left, string right)
    {
        return left + right;
    }
}
