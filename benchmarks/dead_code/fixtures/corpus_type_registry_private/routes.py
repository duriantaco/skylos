class ConversionTable:
    def __init__(self):
        self.entries = {}

    def accepts(self, category, channel="text"):
        def remember(function):
            self.entries[(category, channel)] = function
            return function

        return remember

    def convert(self, value, channel="text"):
        for category in type(value).__mro__:
            function = self.entries.get((category, channel))
            if function is not None:
                return function(value)
        return None
