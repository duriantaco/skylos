import ast
from skylos.rules.danger.danger_access.access_flow import scan


def _scan_code(code, filename="serializers.py"):
    tree = ast.parse(code)
    findings = []
    scan(tree, filename, findings)
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_drf_fields_all():
    code = (
        "from rest_framework import serializers\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = User\n"
        "        fields = '__all__'\n"
    )
    findings = _scan_code(code)
    assert "SKY-D234" in _rule_ids(findings)


def test_drf_fields_explicit_safe():
    code = (
        "from rest_framework import serializers\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = User\n"
        "        fields = ['id', 'name', 'email']\n"
    )
    findings = _scan_code(code)
    assert "SKY-D234" not in _rule_ids(findings)


def test_django_form_fields_all():
    code = (
        "from django import forms\n"
        "class UserForm(forms.ModelForm):\n"
        "    class Meta:\n"
        "        model = User\n"
        "        fields = '__all__'\n"
    )
    findings = _scan_code(code)
    assert "SKY-D234" in _rule_ids(findings)


def test_non_meta_class_safe():
    code = (
        "class Config:\n"
        "    fields = '__all__'\n"
    )
    findings = _scan_code(code)
    assert "SKY-D234" not in _rule_ids(findings)
