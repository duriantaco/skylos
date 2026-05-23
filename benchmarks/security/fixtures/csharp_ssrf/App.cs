using System.Net.Http;
using System.Threading.Tasks;

public class Client
{
    public Task<HttpResponseMessage> Fetch(string url, HttpClient client)
    {
        return client.GetAsync(url);
    }
}
