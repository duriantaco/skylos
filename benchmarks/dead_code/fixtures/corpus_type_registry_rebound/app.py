from routes import Inbox


def run():
    def preserve(kind):
        def wrap(callback):
            return callback

        return wrap

    inbox = Inbox()
    inbox.subscribe = preserve

    @inbox.subscribe(str)
    def consume_alpha(value):
        return value.title()

    def consume_beta(value):
        return str(value)

    print(inbox.handle("message"))


run()
