from sqlalchemy import event


class Engine:
    pass


@event.listens_for(Engine, "connect")
def on_connect(dbapi_connection, connection_record):
    return None


def on_disconnect(connection, record):
    return None


def connection_label(connection, audit_token):
    return str(connection)


connection_label(None, None)
