from repository import create_note


def build_demo_note():
    return create_note("Launch notes", "Operational checklist")


RESULT = build_demo_note()
