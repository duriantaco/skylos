from __future__ import annotations

import pytest

from test.test_security_lookalike_precision import _python_d211, _shell_lines, _ts_lines


@pytest.mark.parametrize(
    "body",
    [
        "return data.password === data.confirm_password;",
        "data.confirm_password = process.env.LOGIN_PASSWORD; return data.password === data.confirm_password;",
        "const alias = data; alias.confirm_password = process.env.LOGIN_PASSWORD; return data.password === data.confirm_password;",
        "Object.assign(data, {confirm_password: process.env.LOGIN_PASSWORD}); return data.password === data.confirm_password;",
    ],
)
def test_confirmation_names_do_not_prove_both_values_are_form_inputs(tmp_path, body):
    code = f"export function authenticate(data) {{ {body} }}\n"
    assert _ts_lines(tmp_path, "SKY-D253", code, "server.ts") == [1]


@pytest.mark.parametrize(
    "code",
    [
        'export function url(process) { return process.env.API ?? "http://localhost:5000"; }',
        'const process = {env:{}}; export const url = process.env.API ?? "http://localhost:5000";',
        'process.env = {}; export const url = process.env.API ?? "http://localhost:5000";',
        'export function url(Bun) { return Bun.env.API ?? "http://localhost:5000"; }',
        'export function url(Deno) { return Deno.env.get("API") ?? "http://localhost:5000"; }',
        'export const url = new.target.env.API ?? "http://localhost:5000";',
    ],
)
def test_environment_spelling_is_not_environment_provenance(tmp_path, code):
    assert _ts_lines(tmp_path, "SKY-D248", code, "app.config.ts") == [1]


@pytest.mark.parametrize(
    "declaration",
    [
        "posts: so.WriteOnlyMapped['Post'] = raw_factory()",
        "posts: so.WriteOnlyMapped['Post'] = so.relationship()\n    if USE_RAW:\n        posts = raw_factory()",
        "posts: so.WriteOnlyMapped['Post'] = so.relationship()\n    for posts in replacements:\n        pass",
        "posts: so.WriteOnlyMapped['Post'] = so.relationship()\n    del posts",
    ],
)
def test_write_only_annotation_does_not_prove_runtime_receiver(tmp_path, declaration):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class User(db.Model):\n    " + declaration + "\n"
        "    def clear(self, name):\n"
        "        db.session.execute(self.posts.delete().where(Post.name == name))\n"
    )
    assert _python_d211(tmp_path, code)


@pytest.mark.parametrize(
    "command", ["npm publish --DRY-RUN", "npm publish --dry-run=false --DRY-RUN"]
)
def test_dry_run_option_names_are_case_sensitive(tmp_path, command):
    assert _shell_lines(tmp_path, command + "\n") == [1]


def _local_form(callback, *, validator="z.string().optional()", extra=""):
    return (
        'import { z } from "zod";\n'
        'import { zodResolver } from "@hookform/resolvers/zod";\n'
        'import { useForm } from "react-hook-form";\n'
        f"const schema = z.object({{password:z.string(),confirmPassword:{validator}}})\n"
        f" .refine({callback});\n"
        "export function Form() { return useForm({resolver:zodResolver(schema)}); }\n"
        + extra
    )


@pytest.mark.parametrize(
    "callback",
    [
        "data => data.password === data.confirmPassword",
        "(data: Form) => !data.password || data.password === data.confirmPassword",
        "({password, confirmPassword}) => password === confirmPassword",
        "({password:pw, confirmPassword:again}) => pw === again",
        "function check({password,confirmPassword=''}) { return password === confirmPassword; }",
    ],
)
def test_proven_local_form_resolver_preserves_confirmation_exemption(
    tmp_path, callback
):
    assert _ts_lines(tmp_path, "SKY-D253", _local_form(callback)) == []


@pytest.mark.parametrize(
    "callback",
    [
        "data => { data.confirmPassword=process.env.LOGIN_PASSWORD; return data.password===data.confirmPassword; }",
        "({password,confirmPassword=process.env.LOGIN_PASSWORD}) => password===confirmPassword",
        "data => { Object.assign(data,{confirmPassword:process.env.LOGIN_PASSWORD}); return data.password===data.confirmPassword; }",
    ],
)
def test_mutating_form_callback_is_not_a_confirmation_proof(tmp_path, callback):
    assert _ts_lines(tmp_path, "SKY-D253", _local_form(callback)) == [5]


@pytest.mark.parametrize(
    "extra",
    [
        "export {schema};\n",
        "export const validate = value => schema.parse(value);\n",
        "storeSchema(schema);\n",
    ],
)
def test_schema_with_non_form_consumers_is_not_suppressed(tmp_path, extra):
    assert _ts_lines(
        tmp_path,
        "SKY-D253",
        _local_form("data => data.password===data.confirmPassword", extra=extra),
    ) == [5]


def test_schema_transform_can_inject_a_secret_into_confirmation(tmp_path):
    code = _local_form(
        "data => data.password===data.confirmPassword",
        validator="z.string().transform(() => process.env.LOGIN_PASSWORD)",
    )
    assert _ts_lines(tmp_path, "SKY-D253", code) == [5]


@pytest.mark.parametrize(
    "replacement",
    [
        "try:\n            work()\n        except RuntimeError as self:\n            pass",
        "import other as self",
        'match value:\n            case {"actor": self}:\n                pass',
    ],
)
def test_receiver_bindings_not_represented_as_name_store_still_report(
    tmp_path, replacement
):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def clear(self, value):\n        " + replacement + "\n"
        "        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


def test_sqlalchemy_prefix_lookalike_does_not_prove_relationship(tmp_path):
    code = (
        "import sqlalchemy.ormevil as so\nfrom app import db\n"
        "class User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


def test_class_local_provider_shadow_does_not_prove_relationship(tmp_path):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class User(db.Model):\n    so = custom_provider\n"
        "    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


@pytest.mark.parametrize("decorator", ["static", "custom_wrapper", "property"])
def test_decorated_method_does_not_prove_implicit_instance_binding(tmp_path, decorator):
    code = (
        "import sqlalchemy.orm as so\nfrom builtins import staticmethod as static\nfrom app import db\n"
        "class User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        f"    @{decorator}\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


@pytest.mark.parametrize(
    "prefix",
    [
        "Object.assign(process.env, {});",
        "const alias = process.env;",
        "globalThis.process = {env:{}};",
        "import.meta.env = {};",
    ],
)
def test_mutation_or_escape_prevents_environment_default_proof(tmp_path, prefix):
    provider = "import.meta" if "import.meta" in prefix else "process"
    code = f'{prefix} export const url = {provider}.env.API ?? "http://localhost:5000";'
    assert _ts_lines(tmp_path, "SKY-D248", code, "app.config.ts") == [1]


def test_zod_namespace_escape_prevents_trusting_form_contract(tmp_path):
    code = _local_form(
        "data => data.password===data.confirmPassword", extra="replaceZod(z);\n"
    )
    assert _ts_lines(tmp_path, "SKY-D253", code) == [5]


@pytest.mark.parametrize(
    "base_body",
    [
        "def __getattribute__(self, name):\n        if name == 'posts':\n            return RawStatements()\n        return object.__getattribute__(self,name)",
        "def replace(self, raw):\n        self.posts = raw",
    ],
)
def test_known_local_base_can_replace_relationship_receiver(tmp_path, base_body):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class RawBase:\n    " + base_body + "\n"
        "class Middle(RawBase):\n    pass\n"
        "class User(Middle, db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


def test_class_decorator_can_replace_relationship_receiver(tmp_path):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "@replace_receivers\nclass User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)


@pytest.mark.parametrize(
    "fields,rebind,expected",
    [
        ("['username', 'email']", "", False),
        ("['username', 'posts']", "", True),
        ("field_names", "", True),
        ("['username']", "field = supplied_name", True),
    ],
)
def test_literal_attribute_update_loop_is_bounded(tmp_path, fields, rebind, expected):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def update(self, data, field_names, supplied_name):\n"
        f"        for field in {fields}:\n"
        + (f"            {rebind}\n" if rebind else "")
        + "            if field in data:\n                setattr(self, field, data[field])\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert bool(_python_d211(tmp_path, code)) is expected


def test_type_only_zod_schema_references_do_not_escape_form_values(tmp_path):
    code = _local_form(
        "data => data.password===data.confirmPassword",
        extra="type Input = z.infer<typeof schema>;\n",
    )
    assert _ts_lines(tmp_path, "SKY-D253", code) == []


def test_for_else_attribute_write_is_not_bounded_by_iteration_values(tmp_path):
    code = (
        "import sqlalchemy.orm as so\nfrom app import db\n"
        "class User(db.Model):\n    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
        "    def replace(self, raw):\n"
        "        for field in ['username']:\n            pass\n"
        "        else:\n            field = 'posts'\n            setattr(self, field, raw)\n"
        "    def clear(self, value):\n        db.session.execute(self.posts.delete().where(Post.name == value))\n"
    )
    assert _python_d211(tmp_path, code)
