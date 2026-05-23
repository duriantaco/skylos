using System.Net.Http;
using System.Threading.Tasks;

public class Client
{
    public Task<HttpResponseMessage> Status(HttpClient client)
    {
        return client.GetAsync("https://api.example.com/status");
    }
}
