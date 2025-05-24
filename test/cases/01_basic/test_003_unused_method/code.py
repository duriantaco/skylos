class TestClass:
    """Class with a mix of used and unused methods."""
    
    def __init__(self):
        """Constructor is implicitly used when class is instantiated."""
        self.value = 42
    
    def used_method(self):
        """This method is called and should not be reported as dead."""
        return self.value * 2
    
    def unused_method(self):
        """This method is never called and should be reported as dead."""
        return self.value * 3
    
    def used_by_other_method(self):
        """This method is called by another method and should not be reported as dead."""
        return self.value * 4
    
    def method_calling_other(self):
        """This method calls another method and is itself called."""
        return self.used_by_other_method() + 10

obj = TestClass()
print(obj.used_method())
print(obj.method_calling_other())