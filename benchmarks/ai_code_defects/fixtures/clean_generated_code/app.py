def validate_token(token):
    if not token:
        raise ValueError("missing token")
    return token


def process_payment(amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"status": "authorized", "amount": amount}


def handler(request):
    token = validate_token(request.headers["Authorization"])
    payment = process_payment(request.amount)
    return {"token": token, "payment": payment}
