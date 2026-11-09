from routes import RouteSet


def run():
    origin = RouteSet()

    @origin.register(str)
    def convert_alpha(value):
        return value.upper()

    branch = origin.fork()

    @origin.register(str)
    def convert_beta(value):
        return value.lower()

    def convert_gamma(value):
        return value.strip()

    print(branch.dispatch("sample"))


run()
