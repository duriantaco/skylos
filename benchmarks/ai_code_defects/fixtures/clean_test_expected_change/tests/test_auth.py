def response_role():
    return "admin"


def test_admin_role_is_exact():
    assert response_role() == "admin"
