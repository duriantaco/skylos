class ExportedClass:
    """This class is exported through the package __init__.py"""

    def __init__(self):
        self.value = "Exported class value"

    def method(self):
        """This method will be used by importers."""
        return self.value

    def unused_method(self):
        """This method is never called by importers."""
        return f"Unused: {self.value}"


class InternalClass:
    """This class is used internally but not exported."""

    def __init__(self):
        self.value = "Internal class value"

    def method(self):
        """This method is called internally."""
        return self.value


class UnusedClass:
    """This class is never used or exported."""

    def __init__(self):
        self.value = "Unused class value"

    def method(self):
        """This method is never called."""
        return self.value


internal_obj = InternalClass()
internal_result = internal_obj.method()
