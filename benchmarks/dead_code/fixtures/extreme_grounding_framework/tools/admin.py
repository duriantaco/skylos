import subprocess


def dangerous_admin(argv=None):
    argv = argv or []
    action = argv[0] if argv else "status"
    command = f"./admin/{action}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def format_admin_status(value):
    return f"status={value}"
