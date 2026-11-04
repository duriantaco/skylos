using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

public class UsersController : Controller
{
    private readonly SqlConnection _connection;

    public UsersController(SqlConnection connection)
    {
        _connection = connection;
    }

    public IActionResult Find(string name)
    {
        var command = new SqlCommand("SELECT email FROM users WHERE name = '" + name + "'", _connection);
        command.ExecuteNonQuery();
        return Ok();
    }
}
