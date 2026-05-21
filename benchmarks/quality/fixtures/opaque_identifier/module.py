def load_account_snapshot(request, repository, audit_log):
    x = request.args.get("account_id")
    if not x:
        audit_log.warning("missing account")
        return {"status": "missing", "account_id": ""}

    audit_log.info("loading account snapshot")
    account = repository.fetch_account(x)
    if account is None:
        return {"status": "missing", "account_id": x}

    owner = repository.fetch_owner(account.owner_id)
    return {
        "status": "active",
        "account_id": x,
        "owner": owner.email,
    }


def coordinate_area(point):
    x = point.get("x", 0)
    y = point.get("y", 0)
    return x * y


def normalize(raw):
    tmp = raw.strip()
    return tmp
