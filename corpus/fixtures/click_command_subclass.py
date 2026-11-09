import click


class DemoCommand(click.Command):
    def invoke(self, ctx):
        return None


class CommandDraft:
    pass


def format_arguments():
    return []
