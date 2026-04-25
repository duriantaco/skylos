from flask import Blueprint, Flask


app = Flask(__name__)
orders = Blueprint("orders", __name__)


@orders.get("/orders/<order_id>")
def show_order(order_id):
    return {"id": order_id}


@app.cli.command("reindex-orders")
def reindex_orders():
    return "queued"


def unused_view_helper():
    return "not registered"


class UnusedFormatter:
    def format(self, value):
        return f"unused:{value}"


app.register_blueprint(orders)
