import sys

from .admin import list_profiles, sync_profile
from .helpers import *


def main():
    code = sys.stdin.read()
    exec(code, globals())
