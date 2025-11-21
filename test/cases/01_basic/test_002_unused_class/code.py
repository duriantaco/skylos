class UsedClass:
    """This class is instantiated and should not be reported as dead code."""

    def __init__(self):
        self.value = 42

    def method(self):
        """This method is called and should not be reported as dead code."""
        return self.value


class UnusedClass:
    """This class is never instantiated and should be reported as dead code."""

    def __init__(self):
        self.value = 100

    def method(self):
        """This method belongs to an unused class and is also dead."""
        return self.value


class ChildClass(UsedClass):
    """This class inherits from UsedClass and is instantiated."""

    def method(self):
        """This method overrides the parent method."""
        return super().method() + 10


obj1 = UsedClass()
print(obj1.method())

obj2 = ChildClass()
print(obj2.method())
