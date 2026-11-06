using Newtonsoft.Json;
public class SettingsFactory {
    public JsonSerializerSettings Build() {
        return new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; // sink
    }
}
