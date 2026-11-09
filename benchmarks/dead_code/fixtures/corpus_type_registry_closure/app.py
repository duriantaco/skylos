from channels import channel


def run():
    register, send = channel()

    @register(int)
    def normalize_alpha(value):
        return value * 2

    @register(str)
    def normalize_beta(value):
        return value.casefold()

    def normalize_gamma(value):
        return repr(value)

    print(send(4))


run()
