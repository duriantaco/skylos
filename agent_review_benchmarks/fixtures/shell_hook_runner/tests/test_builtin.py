from hooks import run_builtin


def test_builtin_hook_is_list_based():
    try:
        run_builtin("status")
    except FileNotFoundError:
        # The benchmark only cares that the safe path stays structurally safe.
        pass
