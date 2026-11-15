class ConversionTable:
    def __init__(self):
        self.entries = {}

    def accepts(self, category):
        def remember(function):
            self.entries[category] = function
            return function

        return remember

    def convert(self, category, value):
        function = self.entries.get(category)
        return function(value) if function is not None else None


class Tagger:
    def __init__(self):
        self.count = 0

    def label(self, name):
        def passthrough(function):
            self.count += 1
            return function

        return passthrough
