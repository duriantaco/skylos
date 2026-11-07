from sqlalchemy import event


class Engine:
    pass


def on_connect(dbapi_connection, connection_record):
    return (dbapi_connection, connection_record)


event.listens_for(Engine, "connect")(on_connect)


def connection_closed(connection, record):
    return (connection, record)


def label_connection(connection, label_style):
    return str(connection)


print(label_connection(None, "compact"))
