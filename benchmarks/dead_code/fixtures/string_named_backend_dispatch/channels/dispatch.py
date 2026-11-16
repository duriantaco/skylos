import sys

from .video import VideoChannel


def run(channel, action_name, target):
    for action in channel.actions:
        if action.name != action_name:
            continue
        for _label, method_name in action.backends:
            return getattr(channel, method_name)(target=target)
    return None


print(run(VideoChannel(), sys.argv[1], sys.argv[2]))
