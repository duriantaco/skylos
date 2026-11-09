public enum TypeNameHandling { None, All }
public class DisplayOptions { public TypeNameHandling TypeNameHandling { get; set; } }
public class SettingsFactory {
    public DisplayOptions Build() {
        return new DisplayOptions { TypeNameHandling = TypeNameHandling.All }; // sink
    }
}
