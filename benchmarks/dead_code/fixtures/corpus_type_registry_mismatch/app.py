from routes import HandlerSet


def run():
    handlers = HandlerSet()

    @handlers.for_type(str)
    def process_alpha(value):
        return value.strip()

    def process_beta(value):
        return value + 1

    print(handlers.send(17))


run()
