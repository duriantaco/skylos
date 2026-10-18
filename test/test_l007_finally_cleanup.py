"""SKY-L007: best-effort deletion in a ``finally`` block is not a hidden failure.

``finally: with suppress(Exception): shutil.rmtree(tmp)`` only gives up on
removing a temporary path after the real work has already succeeded or raised
(agent-pr-bench real-15). Anything else swallowed there is still reported.
"""

import ast
import textwrap

from skylos.analysis.file_processing import set_linter_node_types
from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic_foundation import EmptyErrorHandlerRule


def _rule():
    # Same node-type dispatch as the analyzer's quality pass.
    rule = EmptyErrorHandlerRule()
    set_linter_node_types([rule])
    return rule


def _l007_lines(code: str) -> list[int]:
    visitor = LinterVisitor([_rule()], "app.py")
    visitor.visit(ast.parse(textwrap.dedent(code)))
    return sorted(f["line"] for f in visitor.findings if f["rule_id"] == "SKY-L007")


def test_suppress_around_rmtree_in_finally_is_not_reported():
    code = """
    import shutil
    import tempfile
    from contextlib import suppress

    def run():
        tmp = tempfile.mkdtemp()
        try:
            return work(tmp)
        finally:
            with suppress(Exception):
                shutil.rmtree(tmp)
    """
    assert _l007_lines(code) == []


def test_suppress_around_several_deletions_in_finally_is_not_reported():
    code = """
    import contextlib
    import os
    from pathlib import Path

    def run(path, other: Path):
        try:
            return work(path)
        finally:
            with contextlib.suppress(OSError, Exception):
                os.remove(path)
                other.unlink(missing_ok=True)
    """
    assert _l007_lines(code) == []


def test_try_except_pass_around_deletion_in_finally_is_not_reported():
    code = """
    import shutil

    def run(tmp):
        try:
            return work(tmp)
        finally:
            try:
                shutil.rmtree(tmp)
            except Exception:
                pass
    """
    assert _l007_lines(code) == []


def test_guarded_deletion_in_finally_is_not_reported():
    code = """
    import shutil
    from contextlib import suppress

    def run(tmp):
        try:
            return work(tmp)
        finally:
            if tmp:
                with suppress(Exception):
                    shutil.rmtree(tmp)
    """
    assert _l007_lines(code) == []


def test_deletion_outside_finally_is_still_reported():
    code = """
    import shutil
    from contextlib import suppress

    def run(tmp):
        work(tmp)
        with suppress(Exception):
            shutil.rmtree(tmp)
    """
    assert _l007_lines(code) == [7]


def test_non_deletion_work_in_finally_is_still_reported():
    code = """
    from contextlib import suppress

    def run(path):
        try:
            return work(path)
        finally:
            with suppress(Exception):
                save_results(path)
    """
    assert _l007_lines(code) == [8]


def test_mixed_cleanup_and_other_work_in_finally_is_still_reported():
    code = """
    import shutil

    def run(tmp, conn):
        try:
            return work(tmp)
        finally:
            try:
                shutil.rmtree(tmp)
                conn.commit()
            except Exception:
                pass
    """
    assert _l007_lines(code) == [11]


def test_finally_state_does_not_leak_into_the_next_file():
    rule = _rule()
    first = textwrap.dedent(
        """
        import shutil
        from contextlib import suppress

        def run(tmp):
            try:
                return work(tmp)
            finally:
                with suppress(Exception):
                    shutil.rmtree(tmp)
        """
    )
    second = textwrap.dedent(
        """
        import shutil
        from contextlib import suppress

        def run(tmp):
            with suppress(Exception):
                shutil.rmtree(tmp)
        """
    )
    lines = []
    for code in (first, second):
        visitor = LinterVisitor([rule], "app.py")
        visitor.visit(ast.parse(code))
        lines.append([f["line"] for f in visitor.findings])
    assert lines == [[], [6]]


def test_unlink_on_an_unknown_receiver_is_still_reported():
    # ``r`` may be a Redis client releasing a lock, not a path.
    code = """
    def run(r, lock):
        try:
            return work()
        finally:
            try:
                r.unlink(lock)
            except Exception:
                pass
    """
    assert _l007_lines(code) == [8]


def test_cleanup_method_is_still_reported():
    code = """
    from contextlib import suppress

    def run(self):
        try:
            return work()
        finally:
            with suppress(Exception):
                self.txn.cleanup()
    """
    assert _l007_lines(code) == [8]


def test_bare_except_around_deletion_in_finally_is_still_reported():
    # A bare handler also swallows KeyboardInterrupt and SystemExit.
    code = """
    import os

    def run(path):
        try:
            return work(path)
        finally:
            try:
                os.remove(path)
            except:
                pass
    """
    assert _l007_lines(code) == [10]


def test_suppress_base_exception_around_deletion_is_still_reported():
    code = """
    import shutil
    from contextlib import suppress

    def run(tmp):
        try:
            return work(tmp)
        finally:
            with suppress(BaseException):
                shutil.rmtree(tmp)
    """
    assert _l007_lines(code) == [9]


def test_rmtree_imported_from_shutil_is_a_deletion():
    code = """
    from contextlib import suppress
    from shutil import rmtree as remove_tree

    def run(tmp):
        try:
            return work(tmp)
        finally:
            with suppress(Exception):
                remove_tree(tmp)
    """
    assert _l007_lines(code) == []


def test_homemade_rmtree_is_not_a_deletion():
    code = """
    from contextlib import suppress

    def rmtree(path):
        upload(path)

    def run(tmp):
        try:
            return work(tmp)
        finally:
            with suppress(Exception):
                rmtree(tmp)
    """
    assert _l007_lines(code) == [11]


def test_unlink_on_a_path_built_in_the_function_is_a_deletion():
    code = """
    import pathlib

    def run(tmp):
        out = pathlib.Path(tmp) / "out.txt"
        try:
            return work(out)
        finally:
            try:
                out.unlink()
            except Exception:
                pass
    """
    assert _l007_lines(code) == []


def test_path_name_in_another_function_does_not_make_a_receiver_a_path():
    code = """
    from pathlib import Path

    def build():
        r = Path("x")
        return r

    def run(r, lock):
        try:
            return work()
        finally:
            try:
                r.unlink(lock)
            except Exception:
                pass
    """
    assert _l007_lines(code) == [14]


def test_imported_deletion_name_redefined_in_the_module_is_not_a_deletion():
    code = """
    from os import remove

    def remove(path):
        send_audit_record(path)

    def finish(path):
        try:
            process(path)
        finally:
            try:
                remove(path)
            except Exception:
                pass
    """
    assert _l007_lines(code) == [13]


def test_module_alias_rebound_locally_is_not_a_deletion():
    code = """
    import os

    def finish(path, os):
        try:
            process(path)
        finally:
            try:
                os.remove(path)
            except Exception:
                pass
    """
    assert _l007_lines(code) == [10]


def test_handler_naming_keyboard_interrupt_is_still_reported():
    code = """
    import os

    def run(path):
        try:
            return work(path)
        finally:
            try:
                os.remove(path)
            except (Exception, KeyboardInterrupt):
                pass
    """
    assert _l007_lines(code) == [10]


def test_deletion_whose_argument_changes_state_is_still_reported():
    # ``pop()`` removes the entry even when the deletion fails.
    code = """
    import os

    def flush(self):
        try:
            return work()
        finally:
            try:
                os.remove(self.pending.pop())
            except Exception:
                pass
    """
    assert _l007_lines(code) == [10]


def test_deletion_of_a_joined_path_is_not_reported():
    code = """
    import os
    import shutil

    def run(base, name):
        try:
            return work(base)
        finally:
            try:
                os.remove(os.path.join(base, f"{name}.tmp"))
                shutil.rmtree(str(base))
            except Exception:
                pass
    """
    assert _l007_lines(code) == []
