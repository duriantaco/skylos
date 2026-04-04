class User:
    def __init__(self):
        self._name = "Ada"

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
