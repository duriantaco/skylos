import pytest

from skylos.rules.danger.django_field_providers import django_field_is_available
from skylos.rules.danger.oslo_config_options import ConfigProject


@pytest.mark.parametrize(
    ("loader", "plugin", "expected"),
    [
        ("__import__(name)", "", True),
        ("plugin = __import__(name)", "", False),
        ("__import__(name); exec(source)", "", False),
        ("__import__(name); forms.ChoiceField = replacement", "", False),
        ("__import__(name); setattr(forms, 'ChoiceField', replacement)", "", False),
        ("__import__(name); sys.modules['django'] = replacement", "", False),
        (
            "__import__(name)",
            "from django import forms as f\nf.ChoiceField = other\n",
            False,
        ),
    ],
)
def test_discarded_plugin_import_preserves_declared_field(
    tmp_path, loader, plugin, expected
):
    project = ConfigProject(tmp_path, True)
    sources = {
        "panel.py": "from django import forms\nimport loader\nclass Form(forms.Form):\n    size = forms.ChoiceField(initial=1024)\n",
        "loader.py": f"import sys\nfrom django import forms\ndef load(name, source, replacement):\n    {loader}\n",
        "extension.py": plugin,
    }
    for name, code in sources.items():
        path = tmp_path / name
        path.write_text(code)
        project._add_python(path, code)
    project._index()
    assert (
        django_field_is_available(
            project, project.by_path[tmp_path / "panel.py"], "django.forms.ChoiceField"
        )
        is expected
    )
