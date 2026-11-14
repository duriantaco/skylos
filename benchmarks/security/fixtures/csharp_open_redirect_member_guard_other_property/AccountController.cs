using Microsoft.AspNetCore.Mvc;

public class LoginModel
{
    public string ReturnUrl { get; set; } = "";
    public string FallbackUrl { get; set; } = "";
}

public class AccountController : Controller
{
    public IActionResult Login(LoginModel model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.FallbackUrl);
        }

        return Redirect("~/");
    }

    public IActionResult Switch(LoginModel model, LoginModel other)
    {
        if (Url.IsLocalUrl(other.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return Redirect("~/");
    }
}
