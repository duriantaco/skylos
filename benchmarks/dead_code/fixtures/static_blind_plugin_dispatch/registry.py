HANDLER_PATHS = {
    "pay": "plugins.payments:charge_card",
    "invoice": "plugins.payments:archived_invoice",
    "audit": "plugins.audit:ship_audit",
    "safe-tool": "plugins.tools:run_safe_builtin",
    "mutable-tool": "plugins.tools:run_mutable_registered",
    "fetch": "plugins.network:fetch_url",
    "status": "plugins.network:fetch_fixed_status",
}
