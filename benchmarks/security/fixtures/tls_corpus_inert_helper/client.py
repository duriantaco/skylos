def render(ignore_https_errors=False):
    return {'ignored': ignore_https_errors}

result = render(ignore_https_errors=True)
