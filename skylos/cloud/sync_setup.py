import os
from pathlib import Path


CANCELLED_MESSAGE = "\nCancelled."


def create_precommit_config() -> bool:
    precommit_path = Path(".pre-commit-config.yaml")

    if precommit_path.exists():
        print("  ⚠️  .pre-commit-config.yaml already exists (skipping)")
        return False

    config_content = """# Skylos pre-commit configuration
# Fast staged-only local hook.
# Checks security, secrets, and quality in staged source/config files.
# Full repo and diff-aware enforcement runs in CI.

repos:
  - repo: local
    hooks:
      - id: skylos-gate
        name: Skylos Staged Gate
        entry: skylos
        language: system
        pass_filenames: false
        require_serial: true
        args: ["agent", "pre-commit", "."]
        stages: [pre-commit]
"""

    precommit_path.write_text(config_content)
    print("  ✓ Created .pre-commit-config.yaml")
    return True


def build_pre_push_hook() -> str:
    return """#!/bin/bash
# Fast local push guard only. Full Skylos scans should run manually or in CI.
# Keep this hook shell-only: it must not import or execute repository code.

# Git supplies pending remote updates on stdin. Check the remote ref so
# `git push origin HEAD:main`, force-pushes, and deletes are all blocked.
while read -r local_ref local_sha remote_ref remote_sha; do
    case "$remote_ref" in
        refs/heads/main|refs/heads/master)
            echo ""
            echo "BLOCKED: direct pushes to $remote_ref are not allowed."
            echo "Create a branch and open a pull request instead."
            exit 1
            ;;
    esac
done

exit 0
"""


def cloud_workflow_content() -> str:
    return """name: Skylos Quality Gate

on:
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  skylos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Skylos
        run: python -m pip install skylos

      - name: Pull Skylos Cloud Policy
        run: |
          skylos sync pull || echo "No Skylos Cloud policy available through GitHub OIDC; continuing with local config."
      
      - name: Run Skylos Scan & Upload
        run: |
          skylos . --danger --secrets --quality --ai-defects --upload
        env:
          SKYLOS_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          SKYLOS_BRANCH: ${{ github.event.pull_request.head.ref || github.ref_name }}
"""


def print_free_plan_setup_summary(*, has_git: bool) -> None:
    print("=" * 60)
    print("\n Pro Features Available (Upgrade to enable):\n")

    if has_git:
        print("  🔒 Git hooks - Block bad code on push")
        print("  🔒 Pre-commit - Block bad code on commit")
        print("  🔒 GitHub Actions - Block PRs automatically")
    else:
        print("  ⚠️  Initialize git first: git init")

    print("\n" + "=" * 60)
    print("\n✓ Setup complete!\n")
    print(" What you can do now:\n")
    print("  • Run local scans:")
    print("    $ skylos .\n")
    print("  • View results in dashboard:")
    print("    https://skylos.dev/dashboard\n")
    print("=" * 60 + "\n")


def _prompt_setup_choice(prompt: str, *, default: bool) -> bool | None:
    try:
        response = input(prompt).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(CANCELLED_MESSAGE)
        return None

    if default:
        return response in ["", "y", "yes"]
    return response in ["y", "yes"]


def collect_setup_choices(
    *,
    has_precommit_file: bool,
    has_workflow: bool,
) -> tuple[bool, bool, bool] | None:
    setup_hooks = _prompt_setup_choice(
        "  Install optional pre-push protected-branch hook? "
        "(blocks direct main/master pushes) [Y/n]: ",
        default=True,
    )
    if setup_hooks is None:
        return None

    setup_precommit = False
    if not has_precommit_file:
        setup_precommit = _prompt_setup_choice(
            "  Create staged pre-commit config? (fast local check before commit) [y/N]: ",
            default=False,
        )
        if setup_precommit is None:
            return None
    else:
        print(" * .pre-commit-config.yaml exists (skipping)")

    setup_ci = False
    if not has_workflow:
        setup_ci = _prompt_setup_choice(
            "  Create GitHub Actions? (blocks PR merges) [Y/n]: ",
            default=True,
        )
        if setup_ci is None:
            return None
    else:
        print("  *  .github/workflows/skylos.yml exists (skipping)")

    return setup_hooks, setup_precommit, setup_ci


def install_pre_push_hook(git_dir: Path) -> None:
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-push"
    _write_text_no_symlink(
        hook_path,
        build_pre_push_hook(),
        allowed_dir=hooks_dir,
        mode=0o755,
    )


def write_cloud_workflow() -> None:
    workflow_dir = Path(".github/workflows")
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow_path = workflow_dir / "skylos.yml"
    _write_text_no_symlink(
        workflow_path,
        cloud_workflow_content(),
        allowed_dir=workflow_dir,
    )


def _write_text_no_symlink(
    path: Path,
    content: str,
    *,
    allowed_dir: Path,
    mode: int = 0o644,
) -> None:
    safe_path = _resolve_safe_write_path(path, allowed_dir)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(  # skylos: ignore[SKY-D215] path is contained by _resolve_safe_write_path and opened with O_NOFOLLOW
        safe_path,
        flags,
        mode,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(content)
            os.fchmod(handle.fileno(), mode)
    finally:
        if fd is not None:
            os.close(fd)


def _resolve_safe_write_path(path: Path, allowed_dir: Path) -> Path:
    if path.is_symlink():
        raise OSError(f"Refusing to write symlinked path: {path}")
    if allowed_dir.is_symlink():
        raise OSError(f"Refusing to write through symlinked directory: {allowed_dir}")

    resolved_allowed_dir = allowed_dir.resolve(strict=True)
    resolved_parent = path.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(resolved_allowed_dir)
    except ValueError as exc:
        raise OSError(f"Refusing to write outside {resolved_allowed_dir}: {path}") from exc

    safe_path = resolved_parent / path.name
    if safe_path.is_symlink():
        raise OSError(f"Refusing to write symlinked path: {safe_path}")
    return safe_path


def install_selected_setup_features(
    *,
    git_dir: Path,
    setup_hooks: bool,
    setup_precommit: bool,
    setup_ci: bool,
    has_precommit_file: bool,
) -> None:
    if setup_hooks:
        install_pre_push_hook(git_dir)
        print("  ✓ Installed git hooks (.git/hooks/pre-push)")
    else:
        print(" ✗ Skipped git hooks")

    if setup_precommit:
        created = create_precommit_config()
        if created:
            print("  ✓ Created pre-commit config (.pre-commit-config.yaml)")
    elif not has_precommit_file:
        print("  ✗ Skipped pre-commit config")

    if setup_ci:
        write_cloud_workflow()
        print("  ✓ Created GitHub Actions (.github/workflows/skylos.yml)")
    else:
        print("  ✗ Skipped GitHub Actions")


def print_setup_next_steps(*, setup_precommit: bool, setup_ci: bool) -> None:
    if not setup_precommit and not setup_ci:
        print("\n✓ Setup complete!")
        print("\nRun: skylos . to scan your code\n")
        return

    print("\n Next Steps:\n")
    step_num = 1

    if setup_precommit:
        print(f"{step_num}. Install pre-commit:")
        print("   $ pip install pre-commit")
        print("   $ pre-commit install\n")
        step_num += 1

    if setup_ci:
        print(f"{step_num}. Bind this GitHub repo to the Skylos Cloud project.")
        print(
            "   The workflow uses GitHub OIDC by default; no SKYLOS_TOKEN secret is required."
        )
        print("   Keep SKYLOS_TOKEN only as a legacy fallback for non-GitHub CI.\n")
        step_num += 1

    print(f"{step_num}. Commit and push:")
    print("   $ git add .")
    print("   $ git commit -m 'Add Skylos'")
    print("   $ git push\n")
    print("🎯 Your code is now protected!")
