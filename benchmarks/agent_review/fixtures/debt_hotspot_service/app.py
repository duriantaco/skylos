from ledger import reconcile_account, summarize_account


def handle_dashboard(account):
    summary = summarize_account(account)
    actions = reconcile_account(
        account,
        mode="dashboard",
        include_pending=True,
        dry_run=False,
        emit_metrics=True,
    )
    return {"summary": summary, "actions": actions}
