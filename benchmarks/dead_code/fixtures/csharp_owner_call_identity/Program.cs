namespace Portfolio;

internal static class Program
{
    public static void Main()
    {
        new Primary.Worker().Run();
        new Secondary.Worker();
    }
}
