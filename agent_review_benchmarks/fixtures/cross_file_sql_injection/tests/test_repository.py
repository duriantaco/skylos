from repository import list_recent_users


def test_recent_users_query_shape():
    result = list_recent_users(5)
    assert "LIMIT ?" in result["sql"]
    assert result["params"] == [5]
