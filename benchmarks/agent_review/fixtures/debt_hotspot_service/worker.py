from ledger import reconcile_account


def process_nightly_account(account):
    return reconcile_account(
        account,
        mode="nightly",
        include_pending=True,
        dry_run=False,
        emit_metrics=False,
    )
