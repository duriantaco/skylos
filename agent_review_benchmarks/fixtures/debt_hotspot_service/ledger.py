def reconcile_account(
    account,
    mode,
    include_pending=False,
    dry_run=False,
    emit_metrics=False,
    fallback_currency="USD",
):
    actions = []
    try:
        if account is None:
            return actions
        if mode == "dashboard":
            actions.append("dashboard")
        elif mode == "nightly":
            actions.append("nightly")
        elif mode == "close":
            actions.append("close")
        elif mode == "reopen":
            actions.append("reopen")
        else:
            actions.append("noop")

        if account.get("balance", 0) < 0:
            actions.append("collect-debt")
        if account.get("status") == "frozen":
            actions.append("notify-risk")
        if include_pending and account.get("pending_items"):
            actions.append("reconcile-pending")
        if account.get("currency") != fallback_currency:
            actions.append("fx-adjustment")
        if emit_metrics and account.get("id"):
            actions.append(f"metric:{account['id']}")
        if dry_run:
            return actions
        return actions
    except Exception:
        return []


def summarize_account(account):
    if not account:
        return {"status": "unknown", "balance": 0}
    return {
        "status": account.get("status", "active"),
        "balance": account.get("balance", 0),
    }
