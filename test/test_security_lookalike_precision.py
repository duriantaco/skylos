from __future__ import annotations

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger import scan_ctx
from skylos.visitors.languages.shell import scan_shell_file
from skylos.visitors.languages.typescript import scan_typescript_file


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")


def _ts_lines(
    tmp_path: Path, rule_id: str, code: str, filename: str = "form.tsx"
) -> list[int]:
    path = tmp_path / filename
    _write(path, code)
    danger = scan_typescript_file(str(path))[7]
    return sorted(f["line"] for f in danger if f["rule_id"] == rule_id)


def _shell_lines(tmp_path: Path, code: str) -> list[int]:
    path = tmp_path / "release.sh"
    path.write_text(code, encoding="utf-8")
    findings = scan_shell_file(str(path), {})[7]
    return sorted(f["line"] for f in findings if f["rule_id"] == "SKY-D340")


def _python_d211(tmp_path: Path, code: str) -> list[tuple[int, str]]:
    path = tmp_path / "models.py"
    path.write_text(code, encoding="utf-8")
    findings = scan_ctx(tmp_path, [path])
    return sorted(
        (f["line"], f["severity"]) for f in findings if f["rule_id"] == "SKY-D211"
    )


class TestPasswordConfirmationIsNotTimingOracle:
    @pytest.mark.parametrize(
        "comparison",
        (
            "(data) => data.new_password === data.confirm_password",
            "(data: Form) => !data.password || data.password === data.confirm_password",
            "data => data.password === data.passwordConfirmation",
            "({ password, confirmPassword }: Form) => password === confirmPassword",
            "function check({ password, repeatPassword = '' }) { return password !== repeatPassword; }",
        ),
    )
    def test_generic_confirmation_requires_input_provenance(self, tmp_path, comparison):
        assert _ts_lines(
            tmp_path, "SKY-D253", f"export const check = {comparison};\n"
        ) == [1]

    def test_renamed_operands_remain_outside_name_based_rule(self, tmp_path):
        code = "export const check = ({ password: pw, confirm_password: again }) => pw === again;\n"
        assert _ts_lines(tmp_path, "SKY-D253", code) == []

    def test_zod_refine_confirmation_is_not_reported(self, tmp_path):
        code = (
            'import { z } from "zod";\n'
            'import { zodResolver } from "@hookform/resolvers/zod";\n'
            'import { useForm } from "react-hook-form";\n'
            "const schema = z\n"
            "  .object({ new_password: z.string(), confirm_password: z.string() })\n"
            "  .refine((data) => data.new_password === data.confirm_password, {\n"
            '    message: "The passwords don\'t match",\n'
            "  });\n"
            "export function Form() { return useForm({resolver: zodResolver(schema)}); }\n"
        )
        assert _ts_lines(tmp_path, "SKY-D253", code) == []

    @pytest.mark.parametrize(
        "comparison",
        (
            "(ctx) => ctx.password === ctx.storedPassword",
            "(ctx) => ctx.password === ctx.confirmPasswordHash",
            "(ctx) => ctx.token === ctx.confirmToken",
            "(data, adminPassword) => data.password === adminPassword",
            "(a, b) => a.password === b.confirm_password",
            "(data) => data.password === data.newPassword",
            "(data) => data.password === data.password",
            "(req) => req.body.password === req.body.confirm_password",
            "({ password }, confirmPassword) => password === confirmPassword",
        ),
    )
    def test_comparisons_that_can_involve_a_stored_value_still_report(
        self, tmp_path, comparison
    ):
        assert _ts_lines(
            tmp_path, "SKY-D253", f"export const check = {comparison};\n"
        ) == [1]

    @pytest.mark.parametrize(
        "body",
        (
            "data = load(); return data.password === data.confirm_password;",
            "{ const data = load(); return data.password === data.confirm_password; }",
            "for (data of load()) { return data.password === data.confirm_password; } return false;",
        ),
    )
    def test_rebound_record_still_reports(self, tmp_path, body):
        code = f"export function check(data, load) {{ {body} }}\n"
        assert _ts_lines(tmp_path, "SKY-D253", code) == [1]

    def test_destructured_name_rebound_still_reports(self, tmp_path):
        code = (
            "export function check({ password, confirmPassword }, load) {\n"
            "  password = load();\n"
            "  return password === confirmPassword;\n"
            "}\n"
        )
        assert _ts_lines(tmp_path, "SKY-D253", code) == [3]

    def test_class_fields_and_server_secret_still_report(self, tmp_path):
        code = (
            "export class Form {\n"
            '  password = "";\n'
            '  confirmPassword = "";\n'
            "  check() { return this.password === this.confirmPassword; }\n"
            "}\n"
            "export async function action(formData: FormData) {\n"
            '  "use server";\n'
            '  const token = formData.get("token");\n'
            "  return token === process.env.API_TOKEN;\n"
            "}\n"
        )
        assert _ts_lines(tmp_path, "SKY-D253", code) == [4, 9]


class TestDryRunPublishIsNotAPublish:
    @pytest.mark.parametrize(
        "command",
        (
            "npm publish --dry-run",
            "npm publish --dry-run --tag beta",
            "npm publish --dry-run=true",
            "pnpm publish --dry-run --no-git-checks",
            "cargo publish --dry-run",
            "npm publish --no-dry-run --dry-run",
        ),
    )
    def test_dry_run_is_not_reported(self, tmp_path, command):
        assert _shell_lines(tmp_path, f"#!/bin/bash\n{command}\n") == []

    @pytest.mark.parametrize(
        "command",
        (
            "npm publish",
            "npm publish --dry-run=false",
            "npm publish --no-dry-run",
            "npm publish --dry-run false",
            "npm publish --dry-run --no-dry-run",
            "npm publish -- --dry-run",
            "cargo publish --dry-run=false",
            "twine upload dist/*",
        ),
    )
    def test_real_publish_still_reports(self, tmp_path, command):
        assert _shell_lines(tmp_path, f"#!/bin/bash\n{command}\n") == [2]

    def test_dry_run_beside_real_publish_keeps_the_real_one(self, tmp_path):
        code = (
            "#!/bin/bash\n"
            "npm publish --dry-run\n"
            "read confirm\n"
            'if [[ $confirm == "yes" ]]; then\n'
            "    npm publish\n"
            "fi\n"
        )
        assert _shell_lines(tmp_path, code) == [5]


_WRITE_ONLY_MODELS = """\
import sqlalchemy.orm as so
from sqlalchemy import text
from sqlalchemy.orm import Mapped, WriteOnlyMapped, relationship
from mylib import WriteOnlyMapped as FakeWriteOnly
from app import db


class Notification(db.Model):
    name: so.Mapped[str]


class User(db.Model):
    notifications: so.WriteOnlyMapped["Notification"] = so.relationship(back_populates="user")
    messages: WriteOnlyMapped["Notification"] = relationship()
    tasks: Mapped[list["Notification"]] = relationship(lazy="write_only")
    posts: so.Mapped[list["Notification"]] = so.relationship()
    fakes: FakeWriteOnly["Notification"] = so.relationship()

    def clear_notifications(self, name):
        db.session.execute(self.notifications.delete().where(Notification.name == name))

    def clear_messages(self, name):
        db.session.execute(self.messages.delete().where(Notification.name == name))

    def clear_tasks(self, name):
        db.session.execute(self.tasks.delete().where(Notification.name == name))

    def clear_posts(self, name):
        db.session.execute(self.posts.delete().where(Notification.name == name))

    def clear_fakes(self, name):
        db.session.execute(self.fakes.delete().where(Notification.name == name))

    def clear_raw(self, name):
        db.session.execute(text("DELETE FROM notification WHERE name = '" + name + "'"))

    def clear_other(self, other, name):
        db.session.execute(other.notifications.delete().where(Notification.name == name))

    def clear_string_where(self, name):
        db.session.execute(self.notifications.delete().where("name = '" + name + "'"))

    @staticmethod
    def static_clear(self, name):
        db.session.execute(self.notifications.delete().where(Notification.name == name))

    def clear_rebound(self, name, maker):
        self = maker()
        db.session.execute(self.notifications.delete().where(Notification.name == name))

    def clear_in_closure(self, name):
        def inner(self):
            db.session.execute(self.notifications.delete().where(Notification.name == name))
        return inner


class Reassigned(db.Model):
    notifications: so.WriteOnlyMapped["Notification"] = so.relationship()

    def swap(self, raw):
        self.notifications = raw

    def clear(self, name):
        db.session.execute(self.notifications.delete().where(Notification.name == name))
"""


class TestWriteOnlyRelationshipStatements:
    def test_write_only_collection_statements_are_bound_sql(self, tmp_path):
        lines = [line for line, _ in _python_d211(tmp_path, _WRITE_ONLY_MODELS)]
        assert 20 not in lines
        assert 23 not in lines
        assert 26 not in lines

    def test_unproven_collections_and_string_sql_still_report(self, tmp_path):
        lines = [line for line, _ in _python_d211(tmp_path, _WRITE_ONLY_MODELS)]
        for expected in (29, 32, 35, 38, 41, 45, 49, 53, 64):
            assert expected in lines, expected

    def test_select_insert_update_on_write_only_collection(self, tmp_path):
        code = (
            "import sqlalchemy.orm as so\n"
            "from app import db\n"
            "\n"
            "class User(db.Model):\n"
            "    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
            "\n"
            "    def recent(self, since):\n"
            "        return db.session.execute(self.posts.select().where(Post.ts > since).limit(5))\n"
            "\n"
            "    def add(self, body):\n"
            "        db.session.execute(self.posts.insert().values(body=body))\n"
            "\n"
            "    def touch(self, value):\n"
            "        db.session.execute(self.posts.update().values(flag=value))\n"
        )
        assert _python_d211(tmp_path, code) == []

    def test_write_only_name_reassigned_in_class_body_still_reports(self, tmp_path):
        code = (
            "import sqlalchemy.orm as so\n"
            "from app import db\n"
            "\n"
            "class User(db.Model):\n"
            "    posts: so.WriteOnlyMapped['Post'] = so.relationship()\n"
            "    posts = RawStatements()\n"
            "\n"
            "    def clear(self, since):\n"
            "        db.session.execute(self.posts.delete().where(Post.ts > since))\n"
        )
        assert [line for line, _ in _python_d211(tmp_path, code)] == [9]


class TestEnvironmentDefaultUrl:
    @pytest.mark.parametrize(
        "expression",
        (
            'process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:5173"',
            'process.env.API_URL || "http://127.0.0.1:8000"',
            'import.meta.env.VITE_API ?? "http://localhost:8000"',
            'process.env["API_HOST"] ?? "http://localhost:8001"',
            '(process.env.API_URL ?? ("http://localhost:8002"))',
        ),
    )
    def test_localhost_default_after_env_lookup_is_not_reported(
        self, tmp_path, expression
    ):
        code = f"export const url = {expression};\n"
        assert _ts_lines(tmp_path, "SKY-D248", code, "app.config.ts") == []

    @pytest.mark.parametrize(
        "expression",
        (
            '"http://localhost:8002"',
            '"http://localhost:3000" ?? process.env.X',
            'process.env.MODE === "dev" ? "http://localhost:3001" : "https://prod.example.com"',
            'config.apiUrl ?? "http://localhost:3002"',
            '(process.env.A ?? "") + "http://localhost:3003"',
            'processes.env.API ?? "http://localhost:3004"',
            'process.env.API && "http://localhost:3005"',
            'env.API ?? "http://localhost:3006"',
        ),
    )
    def test_hardcoded_internal_url_still_reports(self, tmp_path, expression):
        code = f"export const url = {expression};\n"
        assert _ts_lines(tmp_path, "SKY-D248", code, "app.config.ts") == [1]
