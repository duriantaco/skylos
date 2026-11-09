from routes import Envelope, Note, Router


def run():
    mailbox = Router()
    other = Router()

    @mailbox.register(Envelope)
    def describe_alpha(value):
        return type(value).__name__

    @other.register(Envelope)
    def describe_beta(value):
        return repr(value)

    def describe_gamma(value):
        return str(value)

    print(mailbox.deliver(Note()))


run()
