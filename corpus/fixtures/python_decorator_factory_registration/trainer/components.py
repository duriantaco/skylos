import functools

import gin
from gin import configurable
from tenacity import retry, stop_after_attempt

from trainer.wrappers import labelled


@gin.configurable("optimizer")
def build_optimizer(learning_rate=0.1):
    return learning_rate


@configurable("network", denylist=["inputs"])
def build_network(inputs, layers=2):
    return inputs, layers


@retry(stop=stop_after_attempt(3))
def unused_retried():
    return 1


@functools.lru_cache(maxsize=4)
def unused_cached():
    return 2


@labelled("x")
def unused_labelled():
    return 3


@gin.timed()
def unused_empty_call():
    return 4


def plain_unused():
    return 5
