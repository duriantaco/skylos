from django.core.validators import validate_email

from models import Request
from middleware.pipeline import dispatch


def update_account(request: Request):
    return dispatch(request, _save_account)


def _save_account(request: Request):
    email = request.json["email"]
    validate_email(email)
    request.user.account.email = email
    request.user.account.save(update_fields=["email"])
    return request.user.account
