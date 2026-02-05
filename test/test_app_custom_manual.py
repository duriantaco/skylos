import pytest


@pytest.fixture
def fixture_a():
    """Used by test_a"""
    return None


@pytest.fixture
def fixture_b():
    """NEVER used by any test"""
    return None


@pytest.fixture
def fixture_c():
    """Used dynamically via getfixturevalue"""
    return "dynamic"


def test_a(fixture_a):
    """Uses fixture_a directly"""
    pass


def test_dynamic(request):
    """Uses fixture_c via getfixturevalue"""
    val = request.getfixturevalue("fixture_c")
    assert val == "dynamic"
