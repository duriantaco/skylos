def run_query(cursor, query, user_id):
    cursor.execute(query, {"id": user_id})
