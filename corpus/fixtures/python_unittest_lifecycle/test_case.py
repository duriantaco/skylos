import unittest


class TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        return None

    @classmethod
    def tearDownClass(cls):
        return None

    def test_lifecycle(self):
        pass


def setUpModule():
    return None


def tearDownModule():
    return None


def prepare_record():
    return None
