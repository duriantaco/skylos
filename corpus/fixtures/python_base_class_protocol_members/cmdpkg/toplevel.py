from distutils.core import Command


class cmd_clean(Command):
    user_options = [("all", "a", "remove everything")]
    negative_opt = {}
    leftovers = []

    def initialize_options(self):
        self.all = None

    def finalize_options(self):
        pass

    def run(self):
        print(self.all)


print(cmd_clean)
