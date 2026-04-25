import subprocess as sp


def list_files():
    return sp.run("ls -la", shell=True, check=False)
