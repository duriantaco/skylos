using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    public IActionResult Next(string redirect)
    {
        return Redirect(redirect);
    }
}
