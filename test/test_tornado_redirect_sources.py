"""RequestHandler reads remain untrusted through assignments and walrus tests."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree


def _redirects(source):
    source = textwrap.dedent(source)
    findings = []
    scan_file_with_tree(ast.parse(source), "app.py", findings, source=source)
    return [finding for finding in findings if finding["rule_id"] == "SKY-D230"]


@pytest.mark.parametrize(
    "method", ["get_argument", "get_query_argument", "get_body_argument"]
)
@pytest.mark.parametrize("walrus", [False, True])
def test_tornado_request_read_reaches_redirect_despite_slash_guard(method, walrus):
    if walrus:
        body = f"""
        if target := self.{method}('next', None):
            if target.startswith('//') or not target.startswith('/'):
                raise ValueError('rejected')
            self.redirect(target)
        """
    else:
        body = f"""
        target = self.{method}('next', '/')
        if target.startswith('//') or not target.startswith('/'):
            raise ValueError('rejected')
        self.redirect(target)
        """
    source = (
        "import tornado\n"
        "class Base(tornado.web.RequestHandler):\n    pass\n"
        "class Login(Base):\n    def get(self):\n"
        + textwrap.indent(textwrap.dedent(body).strip() + "\n", "        ")
    )
    result = _redirects(source)
    assert len(result) == 1
    assert (result[0]["severity"], result[0]["file"], result[0]["symbol"]) == (
        "HIGH",
        "app.py",
        "get",
    )


def test_imported_requesthandler_alias_and_receiver_alias_are_supported():
    assert (
        len(
            _redirects("""
        from tornado.web import RequestHandler as Handler
        class Login(Handler):
            def get(handler):
                target = handler.get_argument('next', '/')
                handler.redirect(target)
    """)
        )
        == 1
    )


@pytest.mark.parametrize(
    "source",
    [
        """
    class Login:
        def get(self):
            self.redirect(self.get_argument('next', '/'))
    """,
        """
    import tornado
    tornado = replacement
    class Login(tornado.web.RequestHandler):
        def get(self):
            self.redirect(self.get_argument('next', '/'))
    """,
        """
    import tornado
    class Login(tornado.web.RequestHandler):
        def get_argument(self, name, default):
            return '/'
        def get(self):
            self.redirect(self.get_argument('next', '/'))
    """,
        """
    import tornado
    class Base(tornado.web.RequestHandler):
        def get_argument(self, name, default):
            return '/'
    class Login(Base):
        def get(self):
            self.redirect(self.get_argument('next', '/'))
    """,
        """
    import tornado
    class Login(tornado.web.RequestHandler):
        def get(self):
            self = replacement
            self.redirect(self.get_argument('next', '/'))
    """,
        """
    import tornado
    class Login(tornado.web.RequestHandler):
        def get(self):
            target = self.get_argument('next', '/')
            if target not in ('/', '/home'):
                raise ValueError('rejected')
            self.redirect(target)
    """,
        """
    import tornado
    class Login(tornado.web.RequestHandler):
        def get(self):
            target = self.get_argument('next', '/')
            target = '/home'
            self.redirect(target)
    """,
    ],
)
def test_unproven_providers_and_bounded_values_stay_quiet(source):
    assert _redirects(source) == []


def test_re_read_after_literal_guard_is_still_untrusted():
    assert (
        len(
            _redirects("""
        import tornado
        class Login(tornado.web.RequestHandler):
            def get(self):
                target = self.get_argument('next', '/')
                if target not in ('/', '/home'):
                    raise ValueError('rejected')
                self.redirect(self.get_argument('next', '/'))
    """)
        )
        == 1
    )


@pytest.mark.parametrize(
    "target", ["'/entry/' + target", "f'/entry/{target}'", "'/a' + target"]
)
def test_fixed_local_path_prefix_cannot_change_redirect_origin(target):
    assert (
        _redirects(
            "from flask import request, redirect\n"
            "def login():\n    target = request.args.get('next')\n"
            f"    return redirect({target})\n"
        )
        == []
    )


@pytest.mark.parametrize(
    "target", ["'/' + target", "'/\\n' + target", "'//' + target", "f'/{target}'"]
)
def test_slash_or_browser_ambiguous_prefix_does_not_bound_origin(target):
    assert (
        len(
            _redirects(
                "from flask import request, redirect\n"
                "def login():\n    target = request.args.get('next')\n"
                f"    return redirect({target})\n"
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    "declarations, base",
    [
        (
            'class Mixin:\n    def get_argument(self, *args):\n        return "/"\n',
            "Mixin, tornado.web.RequestHandler",
        ),
        ("", "tornado.web.RequestHandler"),
    ],
)
def test_mixin_and_assigned_method_overrides_are_not_request_source_proofs(
    declarations, base
):
    assignment = "" if declarations else '    get_argument = lambda *args: "/"\n'
    assert (
        _redirects(
            "import tornado\n"
            + declarations
            + f"class Login({base}):\n"
            + assignment
            + '    def get(self):\n        self.redirect(self.get_argument("next", "/"))\n'
        )
        == []
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "self.get_argument = lambda *args: '/'",
        "setattr(self, 'get_argument', lambda *args: '/')",
        "alias = self\n        alias.get_argument = lambda *args: '/'",
    ],
)
def test_replaced_instance_reader_is_not_a_tornado_source(replacement):
    assert (
        _redirects(
            "import tornado\n"
            "class Login(tornado.web.RequestHandler):\n"
            "    def get(self):\n"
            f"        {replacement}\n"
            "        self.redirect(self.get_argument('next', '/'))\n"
        )
        == []
    )


@pytest.mark.parametrize(
    "rebind",
    [
        "Base = replacement",
        "if flag:\n    Base = replacement",
        "def Base(): pass",
        "from elsewhere import Base",
    ],
)
def test_replaced_local_base_does_not_prove_requesthandler_ancestry(rebind):
    assert (
        _redirects(
            "import tornado\n"
            "class Base(tornado.web.RequestHandler): pass\n"
            f"{rebind}\n"
            "class Login(Base):\n"
            "    def get(self):\n"
            "        self.redirect(self.get_argument('next', '/'))\n"
        )
        == []
    )


@pytest.mark.parametrize("descriptor", ["staticmethod", "classmethod", "alias"])
def test_noninstance_method_does_not_prove_tornado_receiver(descriptor):
    assert (
        _redirects(
            "import tornado\n"
            + ("alias = staticmethod\n" if descriptor == "alias" else "")
            + "class Login(tornado.web.RequestHandler):\n"
            f"    @{descriptor}\n"
            "    def utility(self):\n"
            "        self.redirect(self.get_argument('next', '/'))\n"
        )
        == []
    )


def test_unrelated_reader_write_does_not_change_other_handler_source():
    assert (
        len(
            _redirects("""
        import tornado
        class Local:
            def get(self):
                self.get_argument = lambda *args: '/'
        class Login(tornado.web.RequestHandler):
            def get(self):
                self.redirect(self.get_argument('next', '/'))
    """)
        )
        == 1
    )


def test_generic_staticmethod_parameter_remains_reviewable():
    assert (
        len(
            _redirects("""
        import tornado
        class Login(tornado.web.RequestHandler):
            @staticmethod
            def utility(receiver):
                receiver.redirect(receiver.get_argument('next', '/'))
    """)
        )
        == 1
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "Login.get_argument = lambda *args: '/'",
        "alias = Login\nalias.get_argument = lambda *args: '/'",
        "setattr(Login, 'get_argument', lambda *args: '/')",
    ],
)
def test_replaced_class_reader_is_not_a_tornado_source(replacement):
    assert (
        _redirects(
            "import tornado\n"
            "class Login(tornado.web.RequestHandler):\n"
            "    def get(self):\n"
            "        self.redirect(self.get_argument('next', '/'))\n"
            f"{replacement}\n"
        )
        == []
    )
