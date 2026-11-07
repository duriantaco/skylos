namespace Ledger;

internal class Pipeline
{
    public static void Main()
    {
        var worker = new Pipeline();
        worker.Emit();
    }

    private void Emit() { Normalize(); }
    private void Normalize() { System.Console.WriteLine("ready"); }
    private void Parse() { System.Console.WriteLine("draft"); }
}
