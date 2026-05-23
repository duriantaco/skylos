using System.Diagnostics;

public class Runner
{
    public void Status()
    {
        Process.Start("git", "status");
    }
}
