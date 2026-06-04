def calculate_total(items):
    total = 0
    for item in items:
        total += item["price"] * item.get("quantity", 1)
    return total


def apply_credit(total, credit):
    if credit <= 0:
        return total
    return max(total - credit, 0)
