from models import AuditLog, Note


def create_note(title: str, body: str) -> Note:
    note = Note(title=title, body=body)
    audit = AuditLog(action="note.created")
    return note if audit.action else note
