"""Diff-aware regressions found by the agent-code benchmark (SKY-L021, SKY-A101)."""

import difflib

import pytest

from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening
from skylos.rules.quality.regression import detect_security_regressions


def _diff(old: str, new: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}"
        )
    )


def _l021(old, new, path):
    return [
        f
        for f in detect_security_regressions(_diff(old, new, path), path)
        if f["rule_id"] == "SKY-L021"
    ]


# --- SKY-L021: FastAPI route dependencies -----------------------------------------

FA_USERS_OLD = '''from fastapi import APIRouter, Depends

router = APIRouter()


@router.get(
    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UsersPublic,
)
def read_users(session: SessionDep, skip: int = 0, limit: int = 100) -> Any:
    return UsersPublic(data=[], count=0)
'''


def test_removed_route_decorator_dependency():
    new = FA_USERS_OLD.replace(
        "    dependencies=[Depends(get_current_active_superuser)],\n", ""
    )
    findings = _l021(FA_USERS_OLD, new, "backend/app/api/routes/users.py")
    assert len(findings) == 1
    assert "get_current_active_superuser" in findings[0]["message"]


def test_removed_non_auth_dependency_is_ignored():
    old = FA_USERS_OLD.replace("get_current_active_superuser", "get_db")
    new = old.replace("    dependencies=[Depends(get_db)],\n", "")
    assert _l021(old, new, "backend/app/api/routes/users.py") == []


def test_dependency_moved_to_signature_is_ignored():
    new = FA_USERS_OLD.replace(
        "    dependencies=[Depends(get_current_active_superuser)],\n", ""
    ).replace(
        "def read_users(session: SessionDep,",
        "def read_users(session: SessionDep, _=Depends(get_current_active_superuser),",
    )
    assert _l021(FA_USERS_OLD, new, "backend/app/api/routes/users.py") == []


def test_removed_depends_current_user_parameter():
    old = (
        "@router.get('/me')\n"
        "def me(session: SessionDep, user = Depends(get_current_user)) -> Any:\n"
        "    return user\n"
    )
    new = "@router.get('/me')\ndef me(session: SessionDep) -> Any:\n    return None\n"
    findings = _l021(old, new, "app/routes.py")
    assert findings and "get_current_user" in findings[0]["message"]


# --- SKY-L021: ownership checks -----------------------------------------------------

FA_ITEMS_OLD = '''@router.put("/{id}", response_model=ItemPublic)
def update_item(
    *, session: SessionDep, current_user: CurrentUser, id: uuid.UUID, item_in: ItemUpdate
) -> Any:
    """
    Update an item.
    """
    item = session.get(Item, id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if not current_user.is_superuser and (item.owner_id != current_user.id):
        raise HTTPException(status_code=403, detail="Not enough permissions")
    update_dict = item_in.model_dump(exclude_unset=True)
    return item
'''


def test_removed_ownership_check_fastapi():
    new = FA_ITEMS_OLD.replace(
        "    if not current_user.is_superuser and (item.owner_id != current_user.id):\n"
        '        raise HTTPException(status_code=403, detail="Not enough permissions")\n',
        "",
    )
    findings = _l021(FA_ITEMS_OLD, new, "backend/app/api/routes/items.py")
    assert len(findings) == 1
    assert "Ownership" in findings[0]["message"]


def test_removed_ownership_check_flask():
    old = (
        "@bp.route('/users/<int:id>', methods=['PUT'])\n"
        "@token_auth.login_required\n"
        "def update_user(id):\n"
        "    if token_auth.current_user().id != id:\n"
        "        abort(403)\n"
        "    user = db.get_or_404(User, id)\n"
        "    return user.to_dict()\n"
    )
    new = old.replace(
        "    if token_auth.current_user().id != id:\n        abort(403)\n", ""
    )
    findings = _l021(old, new, "app/api/users.py")
    assert len(findings) == 1
    assert "update_user" in findings[0]["message"]


def test_ownership_check_replaced_by_helper_is_ignored():
    new = FA_ITEMS_OLD.replace(
        "    if not current_user.is_superuser and (item.owner_id != current_user.id):\n"
        '        raise HTTPException(status_code=403, detail="Not enough permissions")\n',
        "    ensure_item_owner(item, current_user)\n",
    )
    assert _l021(FA_ITEMS_OLD, new, "backend/app/api/routes/items.py") == []


def test_not_found_check_removal_is_not_ownership():
    new = FA_ITEMS_OLD.replace(
        "    if not item:\n"
        '        raise HTTPException(status_code=404, detail="Item not found")\n',
        "",
    )
    assert _l021(FA_ITEMS_OLD, new, "backend/app/api/routes/items.py") == []


# --- SKY-L021: Express middleware -----------------------------------------------------

EXPRESS_OLD = """router.put(
  '/articles/:slug',
  auth.required,
  async (req: Request, res: Response, next: NextFunction) => {
    const article = await updateArticle(req.body.article, req.params.slug, req.auth?.user?.id);
    res.json({ article });
  },
);
"""


def test_removed_express_auth_middleware():
    new = EXPRESS_OLD.replace("  auth.required,\n", "")
    findings = _l021(EXPRESS_OLD, new, "src/app/routes/article/article.controller.ts")
    assert len(findings) == 1
    assert "auth.required" in findings[0]["message"]
    assert "/articles/:slug" in findings[0]["message"]


def test_express_auth_swapped_for_other_auth_is_ignored():
    new = EXPRESS_OLD.replace("  auth.required,\n", "  requireAuth,\n")
    assert _l021(EXPRESS_OLD, new, "src/routes.ts") == []


def test_express_route_deleted_entirely_is_ignored():
    assert _l021(EXPRESS_OLD, "", "src/routes.ts") == []


def test_express_non_auth_middleware_removed_is_ignored():
    old = EXPRESS_OLD.replace("auth.required", "rateLimit")
    new = old.replace("  rateLimit,\n", "")
    assert _l021(old, new, "src/routes.ts") == []


# --- SKY-A101: weakened assertions -------------------------------------------------------


def _a101(old, new, path):
    prefix = "def test_x():\n    pass\n"
    return detect_assertion_weakening(_diff(prefix + old, prefix + new, path), path)


@pytest.mark.parametrize(
    "old,new,path,kind",
    [
        (
            "        self.assertFalse(u.check_password('dog'))\n"
            "        self.assertTrue(u.check_password('cat'))\n",
            "        self.assertIsNotNone(u.password_hash)\n",
            "tests.py",
            "behavior_to_existence_assertion",
        ),
        (
            "        self.assertEqual(f1, [p2, p4, p1])\n",
            "        self.assertEqual(len(f1), 3)\n",
            "tests.py",
            "value_to_length_assertion",
        ),
        (
            "    assert response.status_code == 403\n"
            "    content = response.json()\n"
            '    assert content["detail"] == "Not enough permissions"\n',
            "    assert response.status_code in (200, 403)\n",
            "backend/tests/api/routes/test_items.py",
            "assertion_widened_membership",
        ),
        (
            "    expect(items).toEqual([a, b]);\n",
            "    expect(items.length).toEqual(2);\n",
            "src/items.test.ts",
            "value_to_length_assertion",
        ),
    ],
)
def test_weakened_assertions_detected(old, new, path, kind):
    findings = _a101(old, new, path)
    assert [f["metadata"]["weakening_type"] for f in findings] == [kind]


@pytest.mark.parametrize(
    "old,new,path",
    [
        # strengthened
        (
            "    assert response.status_code in (200, 403)\n",
            "    assert response.status_code == 403\n",
            "tests/test_items.py",
        ),
        # equal-strength refactor
        (
            "        self.assertTrue(u.check_password('cat'))\n",
            "        self.assertTrue(u.check_password(password='cat'))\n",
            "tests.py",
        ),
        # length check added alongside the value check
        (
            "        self.assertEqual(f1, [p2, p4, p1])\n",
            "        self.assertEqual(f1, [p2, p4, p1])\n        self.assertEqual(len(f1), 3)\n",
            "tests.py",
        ),
        # exact status replaced with another exact status
        (
            "    assert response.status_code == 403\n",
            "    assert response.status_code == 404\n",
            "tests/test_items.py",
        ),
        # not a test file
        (
            "        self.assertEqual(f1, [p2, p4, p1])\n",
            "        self.assertEqual(len(f1), 3)\n",
            "app/models.py",
        ),
    ],
)
def test_assertion_changes_that_are_not_weakening(old, new, path):
    assert _a101(old, new, path) == []
