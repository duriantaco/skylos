namespace Probe.Events;

public class LogEvent
{
    public string Text = "";

    internal LogEvent Copy()
    {
        return new LogEvent { Text = Text };
    }

    internal LogEvent OrphanClone()
    {
        return new LogEvent { Text = Text };
    }
}
