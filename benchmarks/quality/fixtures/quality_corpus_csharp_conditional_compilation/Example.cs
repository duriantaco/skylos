public static class Example {
    public static void Run() {
#if DEBUG
        return;
#else
        Work();
#endif
    }
    private static void Work() {}
}
