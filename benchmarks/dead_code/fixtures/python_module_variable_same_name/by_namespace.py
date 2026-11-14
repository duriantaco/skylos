import logging

logger = logging.getLogger(__name__)


def lookup(name):
    return globals()[name]


lookup("logger")
