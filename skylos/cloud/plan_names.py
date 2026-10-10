"""User-facing names for Skylos Cloud plans.

Cloud stores the paid plan as ``pro`` but calls it "Workspace" everywhere a
person reads it (skylos-cloud ``src/lib/plan-names.ts``). Print these names,
never "Pro".
"""

PAID_PLAN_NAME = "Workspace"
PRICING_URL = "https://skylos.dev/#pricing"

_PLAN_NAMES = {
    "free": "Free",
    "pro": PAID_PLAN_NAME,
    "enterprise": "Enterprise",
}


def plan_display_name(plan) -> str:
    key = str(plan or "free").strip().lower()
    return _PLAN_NAMES.get(key, key.capitalize())
