from plugins.db import query_all


def charge_card(payload):
    customer = payload.get("customer", "")
    table = payload.get("table", "payments")
    query = f"SELECT id FROM {table} WHERE customer = '{customer}'"
    return query_all(query)


def archived_invoice(payload):
    query = "SELECT id FROM archived_invoices WHERE customer = ?"
    return query_all(query, [payload.get("customer", "")])


def debug_query(payload):
    query = f"SELECT id FROM diagnostics WHERE {payload.get('where', '1=1')}"
    return query_all(query)
