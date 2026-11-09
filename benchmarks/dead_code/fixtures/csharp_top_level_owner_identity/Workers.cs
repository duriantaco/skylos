namespace Primary
{
    internal class Worker
    {
        public void Run() { Process(); }
        private void Process() { System.Console.WriteLine("primary"); }
    }
}

namespace Secondary
{
    internal class Worker
    {
        private void Process() { System.Console.WriteLine("secondary"); }
    }
}
