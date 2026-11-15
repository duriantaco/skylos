namespace Probe.Sinks;

public class Sink
{
    [Traced]
    public string Emit(LogEvent logEvent)
    {
        var copy = logEvent.Copy();
        return Casing.Upper(copy.Text);
    }
}
