using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

public interface IUserRepository
{
    Task<object> GetAsync(string key);
}

public class UsersController : Controller
{
    private readonly IUserRepository _repo;

    public UsersController(IUserRepository repo)
    {
        _repo = repo;
    }

    public async Task<IActionResult> Show(string key)
    {
        var user = await _repo.GetAsync(key);
        return View(user);
    }
}
