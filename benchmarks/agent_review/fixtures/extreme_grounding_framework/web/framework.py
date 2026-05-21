class Request:
    args = {}


class App:
    def route(self, *_args, **_kwargs):
        def decorator(func):
            return func

        return decorator


app = App()
request = Request()
