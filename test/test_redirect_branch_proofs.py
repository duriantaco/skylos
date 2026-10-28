import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree


def _findings(body):
    source = (
        "from flask import redirect, request, url_for\n"
        "from urllib.parse import urlsplit\n"
        "def login(flag):\n"
        + textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
    )
    findings = []
    scan_file_with_tree(ast.parse(source), "app.py", findings, source=source)
    return [finding for finding in findings if finding["rule_id"] == "SKY-D230"]


@pytest.mark.parametrize(
    "body",
    [
        """
        target = request.args.get('next')
        if not target or urlsplit(target).netloc != '':
            target = url_for('index')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if flag:
            target = '/home'
        return redirect(target)
        """,
        """
        if flag:
            target = request.args.get('next')
        else:
            target = '/home'
        return redirect(target)
        """,
        """
        if flag:
            target = '/home'
        else:
            target = request.args.get('next')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        alias = target
        if flag:
            alias = url_for('index')
        return redirect(alias)
        """,
        """
        target = request.args.get('next') if flag else '/home'
        return redirect(target)
        """,
        """
        target = request.args.get('next') or '/home'
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if target not in ('/', '/home'):
            pass
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if target not in ('/', '/home'):
            return redirect('/')
        target = request.args.get('other')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if target not in ('/', request.args.get('allowed')):
            return redirect('/')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        for item in flag:
            if target not in ('/', '/home'):
                return redirect('/')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        try:
            if target not in ('/', '/home'):
                raise ValueError('rejected')
        except ValueError:
            pass
        return redirect(target)
        """,
        """
        target = '/'
        try:
            target = request.args.get('next')
            unknown()
            target = '/'
        except Exception:
            pass
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        with flag:
            if target not in ('/', '/home'):
                raise ValueError('rejected')
        return redirect(target)
        """,
        """
        target = '/'
        for item in flag:
            if item:
                target = request.args.get('next')
                break
            target = '/'
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        match flag:
            case True:
                if target not in ('/', '/home'):
                    return redirect('/')
        return redirect(target)
        """,
    ],
)
def test_possible_request_target_survives_branch_join(body):
    findings = _findings(body)
    assert len(findings) == 1
    assert findings[0]["file"] == "app.py"
    assert findings[0]["symbol"] == "login"
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "body",
    [
        """
        target = request.args.get('next')
        if flag:
            target = '/home'
        else:
            target = url_for('index')
        return redirect(target)
        """,
        """
        if flag:
            target = request.args.get('next')
            return redirect('/')
        else:
            target = '/home'
        return redirect(target)
        """,
        """
        if flag:
            target = '/home'
        else:
            target = request.args.get('next')
            raise ValueError('rejected')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if target not in ('/', '/home'):
            return redirect('/')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        if target in ('/', '/home'):
            return redirect(target)
        return redirect('/')
        """,
        """
        target = request.args.get('next')
        if target != '/home':
            raise ValueError('rejected')
        return redirect(target)
        """,
        """
        target = request.args.get('next')
        target: str = url_for('index')
        return redirect(target)
        """,
    ],
)
def test_only_continuing_safe_paths_reach_redirect(body):
    assert _findings(body) == []
