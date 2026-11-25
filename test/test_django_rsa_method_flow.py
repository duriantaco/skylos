from textwrap import dedent

import pytest

from skylos.rules.danger.danger import scan_ctx


@pytest.mark.parametrize(
    ("argument", "operand", "policy_change", "expected"),
    [
        ("options", "size", "", True),
        ("{}", "size", "", True),
        ("{'modulus': 4096}", "size", "", False),
        ("options", "max(2048, size)", "", False),
        ("options", "size", "Policy.base_fields['modulus'].initial = 4096", False),
        (
            "options",
            "size",
            "forms.Form.__init_subclass__ = classmethod(lambda cls: None)",
            False,
        ),
    ],
)
def test_model_method_forwards_the_actual_policy_to_key_generation(
    tmp_path, argument, operand, policy_change, expected
):
    sources = {
        "policy.py": """
            from django import forms

            class Policy(forms.Form):
                modulus = forms.IntegerField(initial=1024)
                cache_ttl = forms.IntegerField(initial=512)

            def configured(name, values):
                if name not in values:
                    return Policy.base_fields[name].initial
                return int(values[name])
        """,
        "models.py": """
            from django.db import models
            from policy import configured

            class Mailbox(models.Model):
                explicit_bits = models.PositiveIntegerField(null=True)

                def signing_bits(self, saved):
                    selected = self.explicit_bits
                    if selected is not None:
                        return selected
                    return configured('modulus', saved)
        """,
        "sign.py": f"""
            import subprocess
            from models import Mailbox

            def generate(mailbox: Mailbox, options):
                size = mailbox.signing_bits({argument})
                subprocess.run(['openssl', 'genrsa', str({operand})])
        """,
    }
    paths = []
    for name, source in sources.items():
        path = tmp_path / name
        code = dedent(source).lstrip()
        if name == "policy.py" and policy_change:
            code += policy_change + "\n"
        path.write_text(code, encoding="utf-8")
        paths.append(path)

    alerts = [
        (finding["file"], finding["line"], finding["symbol"])
        for finding in scan_ctx(tmp_path, paths)
        if finding["rule_id"] == "SKY-D383"
    ]
    assert alerts == ([(str(tmp_path / "policy.py"), 4, "modulus")] if expected else [])
