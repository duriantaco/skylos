using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    public IActionResult Next()
    {
        return Redirect("/dashboard");
    }
}
