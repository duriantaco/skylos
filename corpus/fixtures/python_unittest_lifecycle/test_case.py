import unittest


class TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        return None

    @classmethod
    def tearDownClass(cls):
        return None


def setUpModule():
    return None


def tearDownModule():
    return None
