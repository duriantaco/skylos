from sqlalchemy import event


class Engine:
    pass


@event.listens_for(Engine, "connect")
def on_connect(dbapi_connection, connection_record):
    return None
