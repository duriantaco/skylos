using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    public IActionResult Login(string returnUrl)
    {
        return LocalRedirect(returnUrl);
    }

    public IActionResult Done(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }
}
