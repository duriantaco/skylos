def run_project_command(argv: list[str]) -> int:
    from skylos.cloud.sync import project_main

    project_main(argv)
    return 0
