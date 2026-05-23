using Microsoft.Data.SqlClient;

public class Repository
{
    public void Find(string sql, SqlConnection connection)
    {
        var command = new SqlCommand(sql, connection);
        command.ExecuteNonQuery();
    }
}
