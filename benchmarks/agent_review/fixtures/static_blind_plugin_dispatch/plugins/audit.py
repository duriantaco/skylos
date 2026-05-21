import subprocess


def ship_audit(payload):
    kind = payload.get("kind", "event")
    command = f"./ship-audit --kind {kind}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def sample_shell(payload):
    command = f"./sample {payload.get('template', 'status')}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)
