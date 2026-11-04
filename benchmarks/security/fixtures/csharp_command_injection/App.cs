using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class JobsController : Controller
{
    public IActionResult Run(string command)
    {
        Process.Start(command);
        return Ok();
    }
}
