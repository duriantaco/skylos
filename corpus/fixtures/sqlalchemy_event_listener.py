from sqlalchemy import event


class Engine:
    pass


def on_connect(dbapi_connection, connection_record):
    return (dbapi_connection, connection_record)


event.listens_for(Engine, "connect")(on_connect)
