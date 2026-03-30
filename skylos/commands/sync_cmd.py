def run_sync_command(argv: list[str]) -> int:
    from skylos.sync import main as sync_main

    sync_main(argv)
    return 0
