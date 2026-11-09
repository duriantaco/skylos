from robot.api.deco import library

class Library:
    def measure(self):
        return 42

    def _reserve(self):
        return 0

Library = library(auto_keywords=True)(Library)
