import pytest


def pytest_addhooks(pluginmanager):
    return pluginmanager


def pytest_cmdline_main(config):
    return 0


def pytest_assertrepr_compare(config, op, left, right):
    return []


def serialize_comparison(value):
    return str(value)


def render_comparison(value, render_style):
    return str(value)


print(render_comparison(1, "compact"))
