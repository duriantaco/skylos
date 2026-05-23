using Microsoft.Data.SqlClient;

public class Repository
{
    public void Find(int id, SqlConnection connection)
    {
        var command = new SqlCommand("SELECT email FROM users WHERE id = @id", connection);
        command.Parameters.AddWithValue("@id", id);
        command.ExecuteNonQuery();
    }
}
