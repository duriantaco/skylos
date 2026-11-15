using Microsoft.AspNetCore.Mvc;

public class LoginModel
{
    public string ReturnUrl { get; set; } = "";
}

public class AccountController : Controller
{
    public IActionResult Login(LoginModel model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return Redirect("~/");
    }
}
