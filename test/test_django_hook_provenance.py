"""Source-only controls for Django hook ownership and effective form fields."""

import pytest

from test.web_framework_fixtures import _scan, _unused


@pytest.mark.parametrize(
    ("base", "hook"),
    [("BaseCommand", "handle"), ("Form", "clean_phone"), ("Model", "save")],
)
def test_local_framework_lookalike_methods_remain_unused(tmp_path, base, hook):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class {base}:
            pass
        class Worker({base}):
            def {hook}(self):
                return 1
            def abandoned(self):
                return 2
        Worker()
    """
        },
    )
    assert f"app.Worker.{hook}" in _unused(result)
    assert "app.Worker.abandoned" in _unused(result)


@pytest.mark.parametrize(
    ("provider", "base", "hook"),
    [
        ("django.core.management.base", "BaseCommand", "handle"),
        ("django.forms", "Form", "clean"),
        ("django.db.models", "Model", "save"),
    ],
)
def test_genuine_imported_django_hooks_remain_recognized(
    tmp_path, provider, base, hook
):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from {provider} import {base} as Parent
        class Worker(Parent):
            def {hook}(self):
                return 1
            def abandoned(self):
                return 2
        Worker()
    """
        },
    )
    assert f"app.Worker.{hook}" not in _unused(result)
    assert "app.Worker.abandoned" in _unused(result)


@pytest.mark.parametrize("declared", [True, False])
def test_form_clean_hook_requires_a_corresponding_field(tmp_path, declared):
    field = "phone = forms.CharField()"
    if not declared:
        field = "unrelated = forms.CharField()"
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class Contact(forms.Form):
            {field}
            def clean_phone(self):
                return "ok"
            def abandoned(self):
                return 2
        Contact().is_valid()
    """
        },
    )
    assert ("app.Contact.clean_phone" in _unused(result)) is not declared
    assert "app.Contact.abandoned" in _unused(result)


def test_inherited_form_field_keeps_clean_hook(tmp_path):
    result = _scan(
        tmp_path,
        {
            "fields.py": """
            from django import forms
            class ContactBase(forms.Form):
                phone = forms.CharField()
        """,
            "app.py": """
            from fields import ContactBase
            class Contact(ContactBase):
                def clean_phone(self):
                    return "ok"
                def clean_missing(self):
                    return "unused"
            Contact().is_valid()
        """,
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.Contact.clean_missing" in _unused(result)


def test_dynamic_form_fields_keep_uncertainty(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        class Contact(forms.Form):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fields["phone"] = forms.CharField()
            def clean_phone(self):
                return "ok"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)


def test_model_form_selected_model_field_keeps_clean_hook(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Person(models.Model):
            phone = models.CharField(max_length=20)
        class Contact(forms.ModelForm):
            class Meta:
                model = Person
                fields = ["phone"]
            def clean_phone(self):
                return "ok"
            def clean_missing(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.Contact.clean_missing" in _unused(result)


def test_imported_project_django_base_keeps_hooks(tmp_path):
    result = _scan(
        tmp_path,
        {
            "parent.py": """
            from django.core.management.base import BaseCommand
            class Parent(BaseCommand):
                pass
        """,
            "app.py": """
            from parent import Parent
            class Worker(Parent):
                def handle(self, *args, **kwargs):
                    return 1
                def abandoned(self):
                    return 2
            Worker()
        """,
        },
    )
    assert "app.Worker.handle" not in _unused(result)
    assert "app.Worker.abandoned" in _unused(result)


@pytest.mark.parametrize("captured", [True, False])
def test_rebinding_a_provider_keeps_only_captured_genuine_base(tmp_path, captured):
    base = "Saved"
    if not captured:
        base = "forms.Form"
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        Saved = forms.Form
        class Ordinary:
            pass
        forms.Form = Ordinary
        class Contact({base}):
            def clean(self):
                return "ok"
        Contact()
    """
        },
    )
    assert ("app.Contact.clean" in _unused(result)) is not captured


def test_model_form_dynamic_fields_remain_uncertain(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Person(models.Model):
            name = models.CharField(max_length=20)
        class Contact(forms.ModelForm):
            class Meta:
                model = Person
                fields = ["name"]
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fields["phone"] = forms.CharField()
            def clean_phone(self):
                return "ok"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)


@pytest.mark.parametrize("selected", ['"__all__"', '["phone"]'])
def test_model_form_selection_preserves_declared_excluded_fields(tmp_path, selected):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        from django.db import models
        class Person(models.Model):
            phone = models.CharField(max_length=20)
        class Contact(forms.ModelForm):
            phone = forms.CharField()
            class Meta:
                model = Person
                fields = {selected}
                exclude = ["phone"]
            def clean_phone(self):
                return "ok"
            def clean_missing(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.Contact.clean_missing" in _unused(result)


@pytest.mark.parametrize("removed_base", ["B", "C"])
def test_form_diamond_field_removal_respects_c3_order(tmp_path, removed_base):
    removed_b = "phone = None"
    removed_c = "pass"
    if removed_base == "C":
        removed_b = "pass"
        removed_c = "phone = None"
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class A(forms.Form):
            phone = forms.CharField()
        class B(A):
            {removed_b}
        class C(A):
            {removed_c}
        class Contact(B, C):
            def clean_phone(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert ("app.Contact.clean_phone" in _unused(result)) == (removed_base == "B")


@pytest.mark.parametrize("genuine", [True, False])
def test_management_parameter_suppression_requires_real_command(tmp_path, genuine):
    prefix = "from django.core.management.base import BaseCommand"
    if not genuine:
        prefix = "from django import forms\nclass BaseCommand:\n    pass"
    result = _scan(
        tmp_path,
        {
            "app.py": prefix
            + """

class Worker(BaseCommand):
    def handle(self, unused):
        return 1
Worker().handle(2)
"""
        },
    )
    assert (
        "app.Worker.handle.unused" in _unused(result, "unused_parameters")
    ) is not genuine


def test_genuine_form_hook_retains_called_helper(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        class Contact(forms.Form):
            phone = forms.CharField()
            def clean_phone(self):
                return format_phone()
        def format_phone():
            return "ok"
        def abandoned():
            return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.format_phone" not in _unused(result)
    assert "app.abandoned" in _unused(result)


@pytest.mark.parametrize("genuine", [True, False])
def test_local_field_class_requires_actual_field_ancestry(tmp_path, genuine):
    parent = "forms.CharField"
    if not genuine:
        parent = "object"
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class PhoneField({parent}):
            pass
        class Contact(forms.Form):
            phone = PhoneField()
            def clean_phone(self):
                return "ok"
            def clean_missing(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert ("app.Contact.clean_phone" in _unused(result)) is not genuine
    assert "app.Contact.clean_missing" in _unused(result)


def test_model_form_all_fields_preserves_only_actual_fields(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Person(models.Model):
            phone = models.CharField(max_length=20)
        class Contact(forms.ModelForm):
            class Meta:
                model = Person
                fields = "__all__"
            def clean_phone(self):
                return "ok"
            def clean_missing(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.Contact.clean_missing" in _unused(result)


def test_project_reexport_preserves_genuine_form_ancestry(tmp_path):
    result = _scan(
        tmp_path,
        {
            "parent.py": "from django.forms import Form as Parent\nAlias = Parent\n",
            "app.py": """
            from parent import Alias
            class Contact(Alias):
                def clean(self):
                    return "ok"
            Contact().is_valid()
        """,
        },
    )
    assert "app.Contact.clean" not in _unused(result)


@pytest.mark.parametrize("table", ["base_fields", "declared_fields"])
def test_module_field_table_mutation_preserves_dynamic_hook_uncertainty(
    tmp_path, table
):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class Contact(forms.Form):
            def clean_phone(self):
                return "ok"
        Contact.{table}["phone"] = forms.CharField()
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)


def test_model_form_exclusion_does_not_mutate_another_forms_model_fields(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Person(models.Model):
            phone = models.CharField(max_length=20)
        class Restricted(forms.ModelForm):
            class Meta:
                model = Person
                fields = "__all__"
                exclude = ["phone"]
            def clean_phone(self):
                return "unused"
        class Contact(forms.ModelForm):
            class Meta:
                model = Person
                fields = "__all__"
            def clean_phone(self):
                return "ok"
        Restricted().is_valid()
        Contact().is_valid()
    """
        },
    )
    assert "app.Restricted.clean_phone" in _unused(result)
    assert "app.Contact.clean_phone" not in _unused(result)


@pytest.mark.parametrize("placement", ["module", "class", "imported"])
def test_form_field_instances_preserve_aliases(tmp_path, placement):
    sources = {}
    prefix = "from django import forms\nPHONE = forms.CharField()\n"
    body = "phone = PHONE"
    if placement == "class":
        prefix = "from django import forms\n"
        body = "source = forms.CharField()\n    phone = source"
    elif placement == "imported":
        sources["fields.py"] = "from django import forms\nPHONE = forms.CharField()\n"
        prefix = "from django import forms\nfrom fields import PHONE\n"
    sources["app.py"] = (
        prefix
        + f"""
class Contact(forms.Form):
    {body}
    def clean_phone(self):
        return "ok"
    def clean_missing(self):
        return "unused"
Contact().is_valid()
"""
    )
    result = _scan(tmp_path, sources)
    assert "app.Contact.clean_phone" not in _unused(result)
    assert "app.Contact.clean_missing" in _unused(result)


@pytest.mark.parametrize(
    "replacement", ["phone = 0", "def phone(self): return 1", "phone = None"]
)
def test_replaced_own_form_field_is_not_dispatched(tmp_path, replacement):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class Contact(forms.Form):
            phone = forms.CharField()
            {replacement}
            def clean_phone(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" in _unused(result)


@pytest.mark.parametrize("replacement", ["phone = 0", "def phone(self): return 1"])
def test_inherited_form_field_survives_non_none_shadow(tmp_path, replacement):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from django import forms
        class Parent(forms.Form):
            phone = forms.CharField()
        class Contact(Parent):
            {replacement}
            def clean_phone(self):
                return "ok"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" not in _unused(result)


def test_model_field_is_not_an_ordinary_form_field(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Contact(forms.Form):
            phone = models.CharField(max_length=20)
            def clean_phone(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" in _unused(result)


def test_model_form_all_fields_omits_uneditable_model_field(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        from django import forms
        from django.db import models
        class Person(models.Model):
            phone = models.CharField(max_length=20, editable=False)
        class Contact(forms.ModelForm):
            class Meta:
                model = Person
                fields = "__all__"
            def clean_phone(self):
                return "unused"
        Contact().is_valid()
    """
        },
    )
    assert "app.Contact.clean_phone" in _unused(result)


@pytest.mark.parametrize(
    ("provider", "base", "hook", "expected_live"),
    [
        ("django.db.models", "Manager", "save", False),
        ("django.db.models", "QuerySet", "save", False),
        ("django.db.models", "QuerySet", "delete", True),
        ("django.forms", "Form", "save", False),
        ("django.db.models", "Model", "get_queryset", False),
        ("django.db.models", "Manager", "get_queryset", True),
        ("django.db.models", "Model", "save", True),
        ("django.forms", "ModelForm", "save", True),
    ],
)
def test_framework_hooks_match_the_specific_provider_role(
    tmp_path, provider, base, hook, expected_live
):
    result = _scan(
        tmp_path,
        {
            "app.py": f"""
        from {provider} import {base} as Parent
        class Worker(Parent):
            def {hook}(self):
                return 1
            def abandoned(self):
                return 2
        Worker()
    """
        },
    )
    assert (f"app.Worker.{hook}" in _unused(result)) is not expected_live
    assert "app.Worker.abandoned" in _unused(result)
