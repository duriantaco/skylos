def test_doctor_names_where_the_cloud_token_comes_from(monkeypatch):
    from unittest.mock import MagicMock

    from skylos.commands import doctor_cmd

    monkeypatch.setattr("skylos.api.get_project_token", lambda: "tok")
    monkeypatch.setattr(doctor_cmd, "_print_credit_status", lambda console, token: None)

    console = MagicMock()
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    doctor_cmd._print_cloud_status(console)
    assert "Cloud connected (saved login)" in console.print.call_args.args[0]

    console = MagicMock()
    monkeypatch.setenv("SKYLOS_TOKEN", "tok")
    doctor_cmd._print_cloud_status(console)
    assert "Cloud connected (SKYLOS_TOKEN set)" in console.print.call_args.args[0]
