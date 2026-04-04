from skylos.llm.repo_activation import build_repo_activation_index


def test_repo_activation_prioritizes_entrypoints_central_modules_and_tests(tmp_path):
    proj = tmp_path / "proj"
    app = proj / "app"
    tests = proj / "tests"
    app.mkdir(parents=True)
    tests.mkdir()

    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text(
        "from app.service import handler\n\n"
        "def run():\n"
        "    return handler('ok')\n\n"
        "if __name__ == '__main__':\n"
        "    run()\n",
        encoding="utf-8",
    )
    (app / "worker.py").write_text(
        "from app.service import handler\n\ndef work():\n    return handler('job')\n",
        encoding="utf-8",
    )
    (app / "service.py").write_text(
        "def handler(value, fallback=None, retries=0, mode='sync', audit=False):\n"
        "    if value == 'a':\n"
        "        return 1\n"
        "    if value == 'b':\n"
        "        return 2\n"
        "    if retries:\n"
        "        return 3\n"
        "    if audit:\n"
        "        return 4\n"
        "    return fallback\n",
        encoding="utf-8",
    )
    (app / "misc.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_service.py").write_text(
        "from app import service\n\n"
        "def test_handler():\n"
        "    assert service.handler('a') == 1\n",
        encoding="utf-8",
    )

    index = build_repo_activation_index(
        [
            app / "main.py",
            app / "worker.py",
            app / "service.py",
            app / "misc.py",
            tests / "test_service.py",
        ],
        project_root=proj,
        static_findings={
            "quality": [
                {"file": str(app / "service.py"), "message": "Function too long"}
            ]
        },
    )

    ranked = [str(p) for p in index.rank_files(max_files=3)]
    assert str(app / "main.py") in ranked
    assert str(app / "service.py") in ranked
    assert str(app / "misc.py") not in ranked

    context = index.context_map_for([app / "service.py"])[
        str((app / "service.py").resolve())
    ]
    assert "imported_by:" in context
    assert "related tests:" in context
    assert "static signals:" in context

    force_full = index.force_full_file_paths_for([app / "main.py", app / "service.py"])
    assert str((app / "main.py").resolve()) in force_full
    assert str((app / "service.py").resolve()) in force_full
