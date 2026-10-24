"""Django hook proofs must follow source edits when a scanner is reused."""

import json
import textwrap

import pytest

from skylos.analyzer import Skylos
from skylos.core.safe_cache_io import write_text_no_symlink
from test.web_framework_fixtures import _django_sources


@pytest.mark.parametrize("initial_field", [True, False])
def test_reused_scanner_refreshes_form_field_proof(tmp_path, initial_field):
    for relative, source in _django_sources().items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())

    path = tmp_path / "shop/contact.py"
    scanner = Skylos()
    for has_field in (initial_field, not initial_field):
        field_source = ""
        if has_field:
            field_source = "    phone = forms.CharField()\n"
        source = (
            "from django import forms\n"
            "class ContactForm(forms.Form):\n"
            + field_source
            + "    def clean_phone(self):\n"
            "        return 'ok'\n"
            "    def unused_helper(self):\n"
            "        return 1\n"
            "ContactForm().is_valid()\n"
        )
        assert write_text_no_symlink(path, source)
        result = json.loads(
            scanner.analyze(str(tmp_path), thr=0, grep_verify=False, trace_file=False)
        )
        assert not result.get("analysis_errors")
        names = {row["full_name"] for row in result.get("unused_functions", [])}
        assert ("shop.contact.ContactForm.clean_phone" in names) == (not has_field)
        assert "shop.contact.ContactForm.unused_helper" in names
