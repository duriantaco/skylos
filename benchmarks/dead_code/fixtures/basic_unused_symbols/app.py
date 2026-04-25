import json
import math


USED_SETTING = "enabled"
UNUSED_SETTING = "disabled"


class UsedWorker:
    def run(self):
        return math.sqrt(16)


class UnusedWorker:
    def run(self):
        return {"unused": True}


def used_helper():
    worker = UsedWorker()
    return worker.run(), USED_SETTING


def unused_helper():
    return "not called"


RESULT = used_helper()
