def render(ignore_https_errors=False):
    return {'ignored': ignore_https_errors}

import mutator
result = render(ignore_https_errors=True)
