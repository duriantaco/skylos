def load_users(cursor):
    query = "SELECT * FROM {} WHERE active = 1".format("users")
    cursor.execute(query)
