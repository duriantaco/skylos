"""Explicit project type checking using the project's installed compiler."""


def run_type_check(path, **kwargs):
    from .comparison import run_type_check as run

    return run(path, **kwargs)


__all__ = ["run_type_check"]
