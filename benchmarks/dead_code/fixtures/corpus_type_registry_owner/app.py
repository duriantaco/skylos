from routes import Router


def run():
    first = Router()
    second = Router()

    @first.register(str)
    def format_alpha(value):
        return value.upper()

    @first.register(bytes)
    def format_beta(value):
        return value.hex()

    @second.register(str)
    def format_gamma(value):
        return value.lower()

    def format_delta(value):
        return str(value)

    print(first.apply("signal"))


run()
