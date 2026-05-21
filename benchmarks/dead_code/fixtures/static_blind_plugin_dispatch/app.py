from dispatcher import dispatch_event


def main(event=None):
    event = event or {"type": "pay", "payload": {}}
    return dispatch_event(event)
