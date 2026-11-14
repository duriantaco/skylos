import sys

from .admin import stop_daemon


def main():
    code = sys.stdin.read()
    exec(code, {})
