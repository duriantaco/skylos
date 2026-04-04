from functools import cached_property


class Settings:
    @cached_property
    def timeout(self):
        return 30
