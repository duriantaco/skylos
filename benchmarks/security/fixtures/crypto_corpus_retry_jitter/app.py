import random

def retry_delay(attempt):
    return 0.5 * attempt + random.uniform(0.0, 0.2)
