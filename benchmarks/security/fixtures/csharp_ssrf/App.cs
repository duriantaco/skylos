using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

public class ProxyController : Controller
{
    private readonly HttpClient _client;

    public ProxyController(HttpClient client)
    {
        _client = client;
    }

    public Task<HttpResponseMessage> Fetch(string url)
    {
        return _client.GetAsync(url);
    }
}
