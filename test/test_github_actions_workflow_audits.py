from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config import scan_config_files
from skylos.rules.config.cicd import actions_expressions as expressions
from skylos.rules.config.cicd import workflow_audits as audits
from skylos.rules.config.cicd.github_actions import scan_github_actions

WORKFLOW = ".github/workflows/ci.yml"
DEPENDABOT = ".github/dependabot.yml"

CASES = {
    "comment_pr_head_write": {
        "files": {
            WORKFLOW: """
name: ok-to-test
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  test:
    if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: npm ci && npm test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_output_ref_secrets": {
        "files": {
            WORKFLOW: """
name: comment build
on: issue_comment
permissions:
  contents: read
  pull-requests: read
jobs:
  build:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - id: pr
        uses: actions/github-script@v7
        with:
          script: |
            const { data } = await github.rest.pulls.get({ ...context.repo, pull_number: context.issue.number })
            core.setOutput('sha', data.head.sha)
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.sha }}
      - run: make build
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "on: issue_comment")],
    },
    "comment_gh_checkout_undeclared": {
        "files": {
            WORKFLOW: """
name: pr command
on:
  issue_comment:
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          gh pr checkout ${{ github.event.issue.number }}
          ./scripts/ci.sh
        env:
          GH_TOKEN: ${{ github.token }}
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_fake_permission_step": {
        "files": {
            WORKFLOW: """
name: fake gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    if: github.event.comment.author_association != 'NONE'
    runs-on: ubuntu-latest
    steps:
      - name: check permission
        run: echo "permission checked"
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/merge
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_shared_prt_ref": {
        "files": {
            WORKFLOW: """
name: shared
on:
  pull_request_target:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
"""
        },
        "expect": [],
    },
    "comment_format_ref": {
        "files": {
            WORKFLOW: """
name: shared fallback
on:
  pull_request_target:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || format('refs/pull/{0}/head', github.event.issue.number) }}
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_reply_only": {
        "files": {
            WORKFLOW: """
name: reply
on:
  issue_comment:
    types: [created]
permissions:
  issues: write
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            await github.rest.issues.createComment({ ...context.repo, issue_number: context.issue.number, body: 'thanks' })
"""
        },
        "expect": [],
    },
    "comment_member_gate": {
        "files": {
            WORKFLOW: """
name: ok-to-test gated
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  test:
    if: >-
      github.event.issue.pull_request &&
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: npm ci && npm test
"""
        },
        "expect": [],
    },
    "comment_read_only": {
        "files": {
            WORKFLOW: """
name: preview
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  lint:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/merge
          persist-credentials: false
      - run: npx eslint .
"""
        },
        "expect": [],
    },
    "comment_permission_step": {
        "files": {
            WORKFLOW: """
name: gated by step
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-cool/check-user-permission@v2
        with:
          require: write
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_default_checkout": {
        "files": {
            WORKFLOW: """
name: base branch only
on:
  issue_comment:
permissions:
  contents: write
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make docs
"""
        },
        "expect": [],
    },
    "prt_cache_write_pr_code": {
        "files": {
            WORKFLOW: """
name: pr build
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v5
        with:
          cache: npm
      - run: npm ci && npm run build
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "cache-mode: write")],
    },
    "comment_cache_write_injection": {
        "files": {
            WORKFLOW: """
name: notes
on:
  issue_comment:
cache-mode: write-only
permissions:
  issues: write
jobs:
  note:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}" > note.txt
      - uses: actions/cache/save@v4
        with:
          path: note.txt
          key: notes-${{ github.run_id }}
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "cache-mode: write-only")],
    },
    "workflow_run_artifacts_cache_write": {
        "files": {
            WORKFLOW: """
name: report
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  actions: read
jobs:
  report:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - uses: actions/cache@v4
        with:
          path: coverage
          key: coverage-${{ github.sha }}
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "cache-mode: write")],
    },
    "prt_cache_write_no_input": {
        "files": {
            WORKFLOW: """
name: triage
on:
  pull_request_target:
permissions:
  pull-requests: write
jobs:
  triage:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v6
        with:
          cache: pip
      - run: python scripts/triage.py
"""
        },
        "expect": [],
    },
    "prt_default_read_cache": {
        "files": {
            WORKFLOW: """
name: pr build default cache
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: actions/setup-node@v5
        with:
          cache: npm
      - run: npm ci && npm test
"""
        },
        "expect": [],
    },
    "push_job_in_prt_workflow": {
        "files": {
            WORKFLOW: """
name: mixed
on:
  push:
  pull_request_target:
permissions:
  contents: read
jobs:
  warm:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make warm-cache
"""
        },
        "expect": [],
    },
    "release_setup_uv_v7": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
      - run: uv build
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "astral-sh/setup-uv@v7")],
    },
    "release_setup_uv_v10": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v10.0.0
      - run: uv build
"""
        },
        "expect": [],
    },
    "release_setup_uv_sha_comment": {
        "files": {
            WORKFLOW: """
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@e58605a9b6da7c637471fab8847a5e5a6b8df081 # v6.4.3
      - run: uv build
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "astral-sh/setup-uv@e58605a9")],
    },
    "release_setup_uv_sha_bare": {
        "files": {
            WORKFLOW: """
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@e58605a9b6da7c637471fab8847a5e5a6b8df081
      - run: uv build
"""
        },
        "expect": [],
    },
    "release_setup_node_v5_npm": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: npm ci && npm run build
""",
            "package.json": '{"name": "demo", "packageManager": "npm@11.6.0"}\n',
        },
        "expect": [("SKY-D308", WORKFLOW, "actions/setup-node@v5")],
    },
    "release_setup_node_v5_pnpm": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: pnpm install && pnpm build
""",
            "package.json": '{"name": "demo", "packageManager": "pnpm@10.0.0"}\n',
        },
        "expect": [],
    },
    "release_setup_node_v4": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm run build
""",
            "package.json": '{"name": "demo", "packageManager": "npm@10.9.0"}\n',
        },
        "expect": [],
    },
    "tag_setup_go": {
        "files": {
            WORKFLOW: """
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  current:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - run: go build ./...
  old:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v3
      - run: go build ./...
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "actions/setup-go@v5")],
    },
    "release_rust_cache": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  restore:
    runs-on: ubuntu-latest
    steps:
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release
  lookup:
    runs-on: ubuntu-latest
    steps:
      - uses: Swatinem/rust-cache@v2
        with:
          lookup-only: true
      - run: cargo build --release
"""
        },
        "expect": [("SKY-D308", WORKFLOW, "Swatinem/rust-cache@v2")],
    },
    "release_cache_mode_none": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
cache-mode: none
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: astral-sh/setup-uv@v7
      - run: uv build
"""
        },
        "expect": [],
    },
    "dependabot_execution": {
        "files": {
            DEPENDABOT: """
version: 2
registries:
  internal:
    type: python-index
    url: https://pypi.example.com/simple
    username: bot
    password: ${{secrets.PYPI_PASSWORD}}
updates:
  - package-ecosystem: pip
    directory: /
    insecure-external-code-execution: allow
    registries: [internal]
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: bundler
    directory: /gems
    insecure-external-code-execution: allow
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: npm
    directory: /web
    insecure-external-code-execution: allow
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
"""
        },
        "expect": [("SKY-D360", DEPENDABOT, "insecure-external-code-execution: allow")],
    },
    "dependabot_cooldowns": {
        "files": {
            DEPENDABOT: """
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 10
      semver-patch-days: 1
  - package-ecosystem: npm
    directory: /docs
    schedule:
      interval: weekly
    cooldown:
      semver-major-days: 14
      semver-minor-days: 10
      semver-patch-days: 7
  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 30
      exclude: ["*"]
  - package-ecosystem: github-actions
    directory: /.github/actions
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
      semver-patch-days: 1
  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 2  # skylos: ignore[SKY-D361]
"""
        },
        "expect": [("SKY-D361", DEPENDABOT, "package-ecosystem: pip")],
    },
    "unredacted_secrets": {
        "files": {
            WORKFLOW: """
name: deploy
on: push
permissions:
  contents: read
env:
  CREDS: ${{ secrets.DEPLOY_CREDS }}
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_TOKEN: ${{ fromJSON(secrets.SERVICE).token }}
    steps:
      - run: ./deploy.sh --user "${{ fromJSON(secrets.SERVICE).user }}"
      - if: contains(fromJSON(secrets.ALLOWED), github.actor)
        run: echo allowed
      - uses: example/login@v1
        with:
          password: ${{ fromJSON(env.CREDS).password }}
      - run: echo "${{ secrets.PLAIN }}"
      - run: echo '${{ toJSON(fromJSON(secrets['CONFIG'])) }}' > config.json
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      TOKEN: ${{ fromJSON(secrets.SERVICE).token }}
"""
        },
        "expect": [
            ("SKY-D362", WORKFLOW, "API_TOKEN: ${{ fromJSON"),
            ("SKY-D362", WORKFLOW, "./deploy.sh --user"),
            ("SKY-D362", WORKFLOW, "password: ${{ fromJSON(env.CREDS)"),
            ("SKY-D362", WORKFLOW, "toJSON(fromJSON(secrets['CONFIG']))"),
        ],
    },
    "obfuscation": {
        "files": {
            WORKFLOW: """
name: tidy
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ${{ fromJSON('["ubuntu-latest"]') }}
    timeout-minutes: ${{ 10 }}
    steps:
      - uses: actions/checkout/./@v4
      - uses: actions/setup-node/../setup-node@v4
      - uses: github/codeql-action//init@v3
      - uses: ./.github/actions/local
      - run: echo "${{ format('{0}', 'release') }}"
      - run: echo "${{ fromJSON(toJSON(github.event.head_commit.message)) }}"
      - if: false
        run: echo disabled
      - if: ${{ 'a' == 'a' }}
        run: echo always
      - run: echo "${{ github.event_name == 'push' && 'prod' || 'dev' }}"
      - run: echo "${{ format('{0}', github.sha) }}"
      - if: contains(fromJSON('["push", "schedule"]'), github.event_name)
        run: echo matched
"""
        },
        "expect": [
            ("SKY-D363", WORKFLOW, "actions/checkout/./@v4"),
            ("SKY-D363", WORKFLOW, "actions/setup-node/../setup-node@v4"),
            ("SKY-D363", WORKFLOW, "github/codeql-action//init@v3"),
            ("SKY-D363", WORKFLOW, "format('{0}', 'release')"),
            ("SKY-D363", WORKFLOW, "fromJSON(toJSON("),
            ("SKY-D363", WORKFLOW, "'a' == 'a'"),
            ("SKY-D363", WORKFLOW, "format('{0}', github.sha)"),
        ],
    },
    "pypa_publish": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
jobs:
  pypi:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
  private:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.ARTIFACTORY }}
          repository-url: https://artifacts.example.com/api/pypi/local
  trusted:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
"""
        },
        "expect": [("SKY-D364", WORKFLOW, "password: ${{ secrets.PYPI_API_TOKEN }}")],
    },
    "python_publish_commands": {
        "files": {
            WORKFLOW: """
name: publish
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  twine:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
  uv:
    runs-on: ubuntu-latest
    steps:
      - run: uv publish --token ${{ secrets.PYPI_TOKEN }}
  internal:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload --repository-url https://pypi.internal.example/legacy/ dist/*
        env:
          TWINE_PASSWORD: ${{ secrets.INTERNAL }}
  oidc:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish
  missing:
    runs-on: ubuntu-latest
    steps:
      - run: uv publish dist/*
"""
        },
        "expect": [
            ("SKY-D364", WORKFLOW, "- run: twine upload dist/*"),
            ("SKY-D364", WORKFLOW, "uv publish --token"),
        ],
    },
    "npm_publish_commands": {
        "files": {
            WORKFLOW: """
name: npm
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  npmjs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  github-packages:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://npm.pkg.github.com
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  self-hosted:
    runs-on: [self-hosted, linux]
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  semantic:
    runs-on: ubuntu-latest
    steps:
      - run: npx semantic-release
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  changesets:
    runs-on: ubuntu-latest
    steps:
      - uses: changesets/action@v1
        with:
          publish: pnpm changeset publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
  npmrc:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_PUBLISH }}
    steps:
      - run: echo "//registry.npmjs.org/:_authToken=${TOKEN}" > ~/.npmrc
      - run: pnpm -r publish --registry https://registry.npmjs.org/
  scripted:
    runs-on: ubuntu-latest
    steps:
      - run: npm run publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  dry:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --dry-run
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
"""
        },
        "expect": [
            ("SKY-D364", WORKFLOW, "npm publish --access public"),
            ("SKY-D364", WORKFLOW, "npx semantic-release"),
            ("SKY-D364", WORKFLOW, "publish: pnpm changeset publish"),
            ("SKY-D364", WORKFLOW, "pnpm -r publish"),
        ],
    },
    "comment_base_ref_output": {
        "files": {
            WORKFLOW: """
name: backport
on:
  issue_comment:
permissions:
  contents: write
jobs:
  backport:
    runs-on: ubuntu-latest
    steps:
      - id: pr
        uses: actions/github-script@v7
        with:
          script: |
            const { data } = await github.rest.pulls.get({ ...context.repo, pull_number: context.issue.number })
            core.setOutput('base', data.base.ref)
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.base }}
      - run: ./scripts/backport.sh
"""
        },
        "expect": [],
    },
    "comment_output_variable": {
        "files": {
            WORKFLOW: """
name: test command
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: pr
        run: |
          sha=$(gh pr view "$NUMBER" --json headRefOid --jq .headRefOid)
          echo "sha=$sha" >> "$GITHUB_OUTPUT"
        env:
          NUMBER: ${{ github.event.issue.number }}
          GH_TOKEN: ${{ github.token }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.sha }}
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_checkout_upload_only": {
        "files": {
            WORKFLOW: """
name: snapshot
on:
  issue_comment:
permissions:
  contents: write
jobs:
  snap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - uses: actions/upload-artifact@v4
        with:
          path: docs
"""
        },
        "expect": [],
    },
    "comment_one_line_checkout": {
        "files": {
            WORKFLOW: """
name: one line
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout ${{ github.event.issue.number }} && npm ci && npm test
        env:
          GH_TOKEN: ${{ github.token }}
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_unread_permission_action": {
        "files": {
            WORKFLOW: """
name: unread gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: check
        uses: actions-cool/check-user-permission@v2
        with:
          require: write
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_permission_output_read": {
        "files": {
            WORKFLOW: """
name: read gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: check
        uses: actions-cool/check-user-permission@v2
        with:
          require: write
      - if: steps.check.outputs.require-result == 'true'
        uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [],
    },
    "comment_gate_continue_on_error": {
        "files": {
            WORKFLOW: """
name: soft gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - continue-on-error: true
        run: gh api "repos/${{ github.repository }}/collaborators/${{ github.actor }}/permission" --jq .permission | grep -q admin
        env:
          GH_TOKEN: ${{ github.token }}
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_echo_gate": {
        "files": {
            WORKFLOW: """
name: echo gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "commenter is ${{ github.event.comment.author_association }} (OWNER or MEMBER may merge)"
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [("SKY-D290", WORKFLOW, "issue_comment:")],
    },
    "comment_script_gate_fails": {
        "files": {
            WORKFLOW: """
name: script gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ ...context.repo, username: context.actor })
            if (!['admin', 'write'].includes(data.permission)) core.setFailed('maintainers only')
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: make test
"""
        },
        "expect": [],
    },
    "review_cache_write": {
        "files": {
            WORKFLOW: """
name: review echo
on:
  pull_request_review:
    types: [submitted]
permissions:
  contents: read
jobs:
  echo:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make
"""
        },
        "expect": [],
    },
    "release_pr_only_job": {
        "files": {
            WORKFLOW: """
name: release
on:
  pull_request:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  test:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
      - run: go test ./...
"""
        },
        "expect": [],
    },
    "release_setup_node_before_checkout": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v5
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
""",
            "package.json": '{"name": "demo", "packageManager": "npm@11.6.0"}\n',
        },
        "expect": [],
    },
    "pypa_minted_token": {
        "files": {
            WORKFLOW: """
name: release
on:
  release:
    types: [published]
permissions:
  id-token: write
jobs:
  pypi:
    runs-on: ubuntu-latest
    steps:
      - id: mint
        uses: tschm/token-mint-action@v1
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ steps.mint.outputs.api-token }}
"""
        },
        "expect": [],
    },
    "python_private_index_env": {
        "files": {
            WORKFLOW: """
name: publish
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  hatch:
    runs-on: ubuntu-latest
    steps:
      - run: hatch publish
        env:
          HATCH_INDEX_REPO: https://pypi.internal.example/legacy/
          HATCH_INDEX_AUTH: ${{ secrets.INTERNAL }}
  pdm:
    runs-on: ubuntu-latest
    steps:
      - run: pdm publish
        env:
          PDM_PUBLISH_REPO: https://pypi.internal.example/legacy/
          PDM_PUBLISH_PASSWORD: ${{ secrets.INTERNAL }}
  maturin:
    runs-on: ubuntu-latest
    steps:
      - run: maturin upload target/wheels/*
        env:
          MATURIN_REPOSITORY_URL: https://pypi.internal.example/legacy/
          MATURIN_PASSWORD: ${{ secrets.INTERNAL }}
"""
        },
        "expect": [],
    },
    "npm_oidc_fallback_token": {
        "files": {
            WORKFLOW: """
name: npm
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - uses: actions/setup-node@v6
        with:
          registry-url: https://registry.npmjs.org
          package-manager-cache: false
      - run: npm ci
      - run: npm publish
"""
        },
        "expect": [("SKY-D364", WORKFLOW, "- run: npm publish")],
    },
    "reusable_npm_publish": {
        "files": {
            WORKFLOW: """
name: reusable npm publish
on:
  workflow_call:
    secrets:
      NPM_TOKEN:
        required: true
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
"""
        },
        "expect": [("SKY-D364", WORKFLOW, "- run: npm publish")],
    },
    "secret_values_not_printed": {
        "files": {
            WORKFLOW: """
name: numbers
on: push
permissions:
  contents: read
jobs:
  env:
    runs-on: ubuntu-latest
    timeout-minutes: ${{ fromJSON(secrets.LIMITS).minutes }}
    continue-on-error: ${{ fromJSON(secrets.LIMITS).soft }}
    strategy:
      max-parallel: ${{ fromJSON(secrets.LIMITS).parallel }}
    steps:
      - run: make
        timeout-minutes: ${{ fromJSON(secrets.LIMITS).step }}
"""
        },
        "expect": [],
    },
    "dependabot_security_only": {
        "files": {
            DEPENDABOT: """
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 0
"""
        },
        "expect": [],
    },
    "reusable_publish": {
        "files": {
            WORKFLOW: """
name: reusable publish
on:
  workflow_call:
    secrets:
      PYPI_TOKEN:
        required: true
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
"""
        },
        "expect": [],
    },
}


def _new_findings(findings):
    """Findings from workflow_audits, apart from the existing rules' own."""
    kept = []
    for finding in findings:
        rule = finding["rule_id"]
        value = str(finding.get("value", ""))
        if rule in {"SKY-D360", "SKY-D361", "SKY-D362", "SKY-D363", "SKY-D364"}:
            kept.append(finding)
        elif rule == "SKY-D290" and value.startswith("issue_comment:"):
            kept.append(finding)
        elif rule == "SKY-D308" and (value.startswith("cache-mode:") or ":default-cache:" in value):
            kept.append(finding)
    return kept


def _materialize(tmp_path, files):
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(target, text.lstrip("\n"), encoding="utf-8")


def _line_of(text, needle, nth=1):
    seen = 0
    for number, line in enumerate(text.lstrip("\n").splitlines(), 1):
        if needle in line:
            seen += 1
            if seen == nth:
                return number
    raise AssertionError(f"{needle!r} not in fixture")


@pytest.mark.parametrize("name", sorted(CASES))
def test_workflow_audit_cases(tmp_path, name):
    case = CASES[name]
    _materialize(tmp_path, case["files"])

    findings = _new_findings(scan_github_actions(tmp_path))

    expected = []
    for item in case["expect"]:
        rule, relative, needle = item[:3]
        nth = 1
        if len(item) > 3:
            nth = item[3]
        expected.append((rule, relative, _line_of(case["files"][relative], needle, nth)))
    actual = [
        (finding["rule_id"], _relative(tmp_path, finding["file"]), finding["line"])
        for finding in findings
    ]
    assert sorted(actual) == sorted(expected)


def _relative(tmp_path, file):
    return Path(file).resolve().relative_to(tmp_path.resolve()).as_posix()


def _scan(tmp_path, files, **kwargs):
    _materialize(tmp_path, files)
    return _new_findings(scan_github_actions(tmp_path, **kwargs))


def test_issue_comment_message_names_job_and_exposure(tmp_path):
    findings = _scan(tmp_path, CASES["comment_output_ref_secrets"]["files"])

    assert len(findings) == 1
    message = findings[0]["message"]
    assert "job build" in message
    assert "output sha of step pr, the pull request head" in message
    assert "secrets DEPLOY_KEY" in message
    assert findings[0]["severity"] == "HIGH"


def test_cache_write_names_the_untrusted_input(tmp_path):
    findings = _scan(tmp_path, CASES["prt_cache_write_pr_code"]["files"])

    assert len(findings) == 1
    assert "pull_request_target" in findings[0]["message"]
    assert "checks out pull request code" in findings[0]["message"]
    assert "actions/setup-node (step 2)" in findings[0]["message"]
    assert findings[0]["severity"] == "HIGH"


def test_called_workflow_cache_write_follows_local_callers(tmp_path):
    files = {
        ".github/workflows/caller.yml": """
name: caller
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  call:
    uses: ./.github/workflows/build.yml
    with:
      ref: ${{ github.event.pull_request.head.sha }}
""",
        ".github/workflows/build.yml": """
name: build
on:
  workflow_call:
    inputs:
      ref:
        type: string
cache-mode: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}
      - run: make
""",
    }
    findings = _scan(tmp_path, files)

    assert [(finding["rule_id"], finding["basename"]) for finding in findings] == [
        ("SKY-D308", "build.yml")
    ]
    assert "passed in by a caller" in findings[0]["message"]

    capped = dict(files)
    capped[".github/workflows/caller.yml"] = files[".github/workflows/caller.yml"].replace(
        "    uses: ./.github", "    cache-mode: read\n    uses: ./.github"
    )
    assert _scan(tmp_path, capped) == []


def test_dependabot_execution_needs_registries_to_matter(tmp_path):
    findings = _scan(tmp_path, CASES["dependabot_execution"]["files"])

    assert [(finding["severity"], finding["provider"]) for finding in findings] == [
        ("HIGH", "dependabot")
    ]
    assert "credentials of the private registries" in findings[0]["message"]


def test_dependabot_discovery_respects_changed_files_and_single_file(tmp_path):
    _materialize(tmp_path, CASES["dependabot_cooldowns"]["files"])
    dependabot = tmp_path / ".github" / "dependabot.yml"

    assert scan_github_actions(tmp_path, changed_files={"README.md"}) == []
    changed = _new_findings(
        scan_github_actions(tmp_path, changed_files={".github/dependabot.yml"})
    )
    assert len(changed) == 1
    single = _new_findings(scan_config_files(dependabot))
    assert [finding["message"] for finding in single] == [changed[0]["message"]]
    assert _new_findings(
        scan_github_actions(tmp_path, ignore={"SKY-D360", "SKY-D361"})
    ) == []


def test_cooldown_finding_lists_every_short_entry_once(tmp_path):
    findings = _scan(tmp_path, CASES["dependabot_cooldowns"]["files"])

    assert len(findings) == 1
    message = findings[0]["message"]
    assert "pip in / after 3 day(s) (no cooldown is set" in message
    assert "npm in / after 1 day(s) (semver-patch-days: 1)" in message
    assert "docker in / after 0 day(s) (exclude: ['*']" in message
    assert "/docs" not in message
    assert "/.github/actions" not in message
    assert "cargo" not in message
    assert findings[0]["severity"] == "LOW"


def test_dependabot_yaml_extension_and_nested_copies(tmp_path):
    text = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
    _materialize(tmp_path, {".github/dependabot.yaml": text, "vendor/x/.github/dependabot.yml": text})

    findings = _new_findings(scan_github_actions(tmp_path))

    assert [(finding["rule_id"], finding["basename"]) for finding in findings] == [
        ("SKY-D361", "dependabot.yaml")
    ]


@pytest.mark.parametrize(
    ("ecosystem", "cooldown", "days"),
    [
        ("npm", None, 3),
        ("npm", {"default-days": 7}, 7),
        ("npm", {"semver-major-days": 30, "semver-minor-days": 9, "semver-patch-days": 8}, 8),
        ("npm", {"default-days": 14, "semver-minor-days": 2}, 2),
        ("npm", {"semver-major-days": 30}, 3),
        ("docker", {"default-days": 7, "semver-patch-days": 1}, 7),
        ("docker", {"default-days": 5}, 5),
        ("future-ecosystem", {"semver-major-days": 9, "semver-minor-days": 9, "semver-patch-days": 9}, 9),
        ("future-ecosystem", {"default-days": 8, "semver-patch-days": 1}, 8),
        ("pip", {"default-days": 30, "exclude": ["*"]}, 0),
        ("pip", {"default-days": 30, "exclude": ["internal-*"]}, 30),
        ("pip", {"default-days": 30, "include": ["lodash"]}, 3),
        ("pip", {"default-days": 30, "include": ["*"]}, 30),
    ],
)
def test_effective_cooldown(ecosystem, cooldown, days):
    update = {"package-ecosystem": ecosystem}
    if cooldown is not None:
        update["cooldown"] = cooldown

    assert audits._effective_cooldown(update, 0, ecosystem).days == days


@pytest.mark.parametrize(
    ("cooldown",),
    [({"default-days": "seven"},), ({"default-days": -1},), ({"semver-patch-days": True},), ("7",)],
)
def test_effective_cooldown_leaves_invalid_values_alone(cooldown):
    assert audits._effective_cooldown({"cooldown": cooldown}, 0, "npm") is None


@pytest.mark.parametrize(
    ("source", "constants"),
    [
        ("format('{0}-{1}', 'a', 'b')", ["format('{0}-{1}', 'a', 'b')"]),
        ("'a' == 'A'", ["'a' == 'A'"]),
        ("toJSON('x')", ["toJSON('x')"]),
        ("fromJSON('{\"a\": 1}').a", ["fromJSON('{\"a\": 1}').a"]),
        ("contains(fromJSON('[\"a\"]'), 'a')", ["contains(fromJSON('[\"a\"]'), 'a')"]),
        ("!true", ["!true"]),
        ("github.event_name == format('{0}', 'push')", ["format('{0}', 'push')"]),
        ("true", []),
        ("'ubuntu-latest'", []),
        ("fromJSON('[1, 2]')", []),
        ("contains(fromJSON('[\"OWNER\"]'), github.event.comment.author_association)", []),
        ("false && github.event_name == 'push'", []),
        ("inputs.flag || 'default'", []),
        ("hashFiles('**/go.sum')", []),
        ("format('{0}', 'a', 'b') == 'a'", ["format('{0}', 'a', 'b') == 'a'"]),
        ("format('{1}', 'a')", []),
        ("format('{\u00b2}', 'a')", []),
    ],
)
def test_constant_folding(source, constants):
    found = audits._foldings(expressions.parse_expression(source))
    assert [part for part, message in found if "always evaluates" in message] == constants


@pytest.mark.parametrize(
    ("source", "value"),
    [
        ("format('{0}{{x}}', 'a')", "a{x}"),
        ("join(fromJSON('[1, true, null]'), '+')", "1+true+"),
        ("1 == '1'", True),
        ("'abc' < 'ABD'", True),
        ("null == 0", True),
        ("fromJSON('[]') == fromJSON('[]')", False),
        ("case(false, 'a', 'b')", "b"),
        ("startsWith('Refs/Tags/v1', 'refs/tags/')", True),
        ("'' || 'fallback'", "fallback"),
        ("0 && 'never'", 0),
        ("'_' < 'a'", False),
        ("'1_0' == 10", False),
        ("' 0x10 ' == 16", True),
    ],
)
def test_constant_values(source, value):
    assert audits._fold(expressions.parse_expression(source), 0) == value


@pytest.mark.parametrize(
    ("source", "decoded"),
    [
        ("fromJSON(secrets.A).b", ["fromJSON(secrets.A).b"]),
        ("fromJSON(secrets.A)", ["fromJSON(secrets.A)"]),
        ("fromJSON(secrets.A)['b'][0]", ["fromJSON(secrets.A)['b'][0]"]),
        ("format('{0}', fromJSON(secrets.A).b)", ["fromJSON(secrets.A).b"]),
        ("fromJSON(secrets.A || '{}').b", ["fromJSON(secrets.A || '{}').b"]),
        ("secrets.A", []),
        ("fromJSON(secrets.A).b == 'x'", []),
        ("contains(fromJSON(secrets.A), github.actor)", []),
        ("fromJSON(vars.A).b", []),
        ("fromJSON(github.event.issue.body).b", []),
    ],
)
def test_decoded_secrets(source, decoded):
    found = audits._decoded_secrets(expressions.parse_expression(source), [])
    assert [text for text, _secret in found] == decoded


@pytest.mark.parametrize(
    ("command", "kind"),
    [
        ("twine upload dist/*", ("pypi", "twine upload")),
        ("python3.12 -m twine upload dist/*", ("pypi", "twine upload")),
        ("pipx run twine==6.1.0 upload dist/*", ("pypi", "twine upload")),
        ("uvx twine@6.1.0 upload dist/*", ("pypi", "twine upload")),
        ("uv run --with twine twine upload dist/*", ("pypi", "twine upload")),
        ("uv publish", ("pypi", "uv publish")),
        ("poetry publish --build", ("pypi", "poetry publish")),
        ("hatch publish", ("pypi", "hatch publish")),
        ("maturin upload target/wheels/*", ("pypi", "maturin upload")),
        ("npm publish --provenance", ("npm", "npm publish")),
        ("pnpm -r publish", ("npm", "pnpm publish")),
        ("yarn npm publish", ("npm", "yarn publish")),
        ("npx -y npm@11 publish", ("npm", "npm publish")),
        ("pnpm changeset publish", ("npm", "changeset publish")),
        ("npx --yes -p semantic-release -p @semantic-release/npm semantic-release", ("npm", "semantic-release")),
        ("twine check dist/*", None),
        ("python -c 'import twine' upload", None),
        ("uv publish --dry-run", None),
        ("npm run publish", None),
        ("pnpm exec publish", None),
        ("npm view publish", None),
        ("pnpm --filter web publish", ("npm", "pnpm publish")),
        ("pnpm dlx semantic-release", ("npm", "semantic-release")),
        ("npx semantic-release --dry-run", None),
        ("npx -p semantic-release echo", None),
        ("cargo publish", None),
    ],
)
def test_publish_command_recognition(command, kind):
    found = list(audits._publish_commands(command))
    if kind is None:
        assert found == []
    else:
        assert [(item.registry, item.command) for item in found] == [kind]


@pytest.mark.parametrize(
    ("uses", "comment", "version"),
    [
        ("astral-sh/setup-uv@v7", "", (7.0,)),
        ("astral-sh/setup-uv@v6.4.3", "", (6.0, 4.0, 3.0)),
        ("actions/setup-node@main", "", audits._NEWEST),
        ("actions/setup-node@" + "a" * 40, "# v5.0.0", (5.0, 0.0, 0.0)),
        ("actions/setup-node@" + "a" * 40, "# tag=v6", (6.0,)),
        ("actions/setup-node@" + "a" * 40, "# bumped 2026 by bot", None),
        ("actions/setup-node@" + "a" * 40, "", None),
        ("actions/setup-node@feature-branch", "", None),
    ],
)
def test_reference_versions(uses, comment, version):
    assert audits._ref_version(uses, comment) == version


def test_inline_ignore_suppresses_new_rules(tmp_path):
    files = {
        WORKFLOW: """
name: tidy
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # skylos: ignore[SKY-D363]
      - uses: actions/checkout/./@v4
      - uses: actions/setup-node/./@v4  # skylos: ignore[SKY-D363]
      - uses: actions/setup-python/./@v6
"""
    }
    findings = _scan(tmp_path, files)

    assert [finding["value"] for finding in findings] == ["actions/setup-python/./@v6"]


def test_composite_action_gets_path_and_expression_checks_only(tmp_path):
    files = {
        "action.yml": """
name: composite
description: demo
runs:
  using: composite
  steps:
    - uses: actions/cache/./@v4
      with:
        path: x
        key: ${{ format('{0}', 'k') }}
    - run: echo "${{ fromJSON(inputs.creds).user }}"
      shell: bash
"""
    }
    findings = _scan(tmp_path, files)

    assert sorted(finding["rule_id"] for finding in findings) == ["SKY-D363", "SKY-D363"]


@pytest.mark.parametrize(
    ("uses", "off"),
    [
        ("jdx/mise-action@v3", "cache: false"),
        ("actions-rust-lang/setup-rust-toolchain@v1", "cache: false"),
        ("mlugg/setup-zig@v2", "use-cache: false"),
        ("oven-sh/setup-bun@v2", "no-cache: true"),
        ("gradle/actions/setup-gradle@v4", "cache-disabled: true"),
        ("ramsey/composer-install@v3", "ignore-cache: yes"),
    ],
)
def test_release_restores_caches_that_actions_turn_on(tmp_path, uses, off):
    template = """
name: release
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: {uses}
{config}      - run: make dist
"""
    on = _scan(tmp_path, {WORKFLOW: template.format(uses=uses, config="")})
    assert [finding["line"] for finding in on] == [11]

    stopped = template.format(uses=uses, config=f"        with:\n          {off}\n")
    assert _scan(tmp_path, {WORKFLOW: stopped}) == []

    dynamic = template.format(
        uses=uses, config=f"        with:\n          {off.split(':')[0]}: ${{{{ inputs.x }}}}\n"
    )
    assert _scan(tmp_path, {WORKFLOW: dynamic}) == []


def test_cache_write_ignores_steps_outsiders_cannot_reach(tmp_path):
    workflow = CASES["prt_cache_write_pr_code"]["files"][WORKFLOW]
    gated = workflow.replace(
        "    steps:\n",
        "    steps:\n      - uses: prince-chrismc/check-actor-permissions-action@v3\n"
        "        with:\n          permission: write\n",
        1,
    )
    assert _scan(tmp_path, {WORKFLOW: gated}) == []

    fake = workflow.replace(
        "    steps:\n",
        "    steps:\n      - name: permission check\n        run: echo ok\n",
        1,
    )
    assert [finding["rule_id"] for finding in _scan(tmp_path, {WORKFLOW: fake})] == [
        "SKY-D308"
    ]


def test_npm_token_beside_trusted_publishing_is_low(tmp_path):
    findings = _scan(tmp_path, CASES["npm_oidc_fallback_token"]["files"])

    assert [finding["severity"] for finding in findings] == ["LOW"]
    assert "token is only a fallback" in findings[0]["message"]


def test_called_workflow_inherits_or_is_capped_by_caller_cache_mode(tmp_path):
    caller = """
name: caller
on:
  issue_comment:
permissions:
  contents: read
jobs:
  call:
{mode}    uses: ./.github/workflows/build.yml
"""
    callee = """
name: build
on:
  workflow_call:
{mode}jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{{{ github.event.comment.body }}}}"
"""
    cases = [
        ("    cache-mode: write\n", "", 1),
        ("    cache-mode: write\n", "cache-mode: write\n", 1),
        ("    cache-mode: write-only\n", "cache-mode: write\n", 0),
        ("    cache-mode: read\n", "cache-mode: write\n", 0),
        ("", "cache-mode: write-only\n", 1),
        ("", "", 0),
    ]
    for caller_mode, callee_mode, expected in cases:
        files = {
            ".github/workflows/caller.yml": caller.format(mode=caller_mode),
            ".github/workflows/build.yml": callee.format(mode=callee_mode),
        }
        found = [item for item in _scan(tmp_path, files) if item["basename"] == "build.yml"]
        assert len(found) == expected, (caller_mode, callee_mode)


GATE_WORKFLOW = """
name: gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
{gate}      - {target_if}uses: actions/checkout@v4
        with:
          ref: refs/pull/${{{{ github.event.issue.number }}}}/head
      - run: make test
"""


@pytest.mark.parametrize(
    ("gate", "target_if", "reported"),
    [
        ("      - uses: attacker/permission-printer@v1\n", "", True),
        (
            "      - uses: actions-cool/check-user-permission@v2\n"
            "        with:\n          require: write\n          error-if-missing: true\n",
            "",
            False,
        ),
        (
            "      - uses: actions-cool/check-user-permission@v2\n"
            "        with:\n          require: write\n          error-if-missing: true\n"
            "          username: release-bot\n",
            "",
            True,
        ),
        ("      - uses: sushichop/action-repository-permission@v2\n", "", False),
        (
            "      - uses: sushichop/action-repository-permission@v2\n"
            "        with:\n          relax: true\n",
            "",
            True,
        ),
        (
            "      - uses: xt0rted/slash-command-action@v2\n"
            "        with:\n          command: test\n          permission-level: read\n",
            "",
            True,
        ),
        (
            "      - uses: xt0rted/slash-command-action@v2\n"
            "        with:\n          command: test\n",
            "",
            False,
        ),
        (
            "      - uses: prince-chrismc/check-actor-permissions-action@v3\n"
            "        with:\n          permission: write\n",
            "if: always()\n        ",
            True,
        ),
        (
            "      - id: auth\n        uses: morfien101/actions-authorized-user@v3\n"
            "        with:\n          username: ${{ github.actor }}\n          team: core\n",
            "if: steps.auth.outputs.authorized == 'true'\n        ",
            False,
        ),
        (
            "      - id: auth\n        uses: morfien101/actions-authorized-user@v3\n"
            "        with:\n          username: ${{ github.actor }}\n          team: core\n",
            "if: steps.auth.outputs.authorized != 'true'\n        ",
            True,
        ),
        (
            "      - run: |\n          echo \"authorization checked for $ACTOR\"\n"
            "          gh api repos/o/r/collaborators/$ACTOR/permission\n",
            "",
            True,
        ),
        (
            "      - run: |\n          perm=$(gh api repos/o/r/collaborators/$ACTOR/permission --jq .permission)\n"
            "          [ \"$perm\" = admin ] || exit 1\n",
            "",
            False,
        ),
    ],
)
def test_only_verified_permission_checks_gate_outsiders(tmp_path, gate, target_if, reported):
    files = {WORKFLOW: GATE_WORKFLOW.format(gate=gate, target_if=target_if)}
    found = [finding["rule_id"] for finding in _scan(tmp_path, files)]
    assert found == (["SKY-D290"] * reported)


def test_needed_job_gates_only_with_a_failing_check(tmp_path):
    template = """
name: needs gate
on:
  issue_comment:
permissions:
  contents: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
{gate}
  test:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{{{ github.event.issue.number }}}}/head
      - run: make test
"""
    failing = (
        "      - uses: prince-chrismc/check-actor-permissions-action@v3\n"
        "        with:\n          permission: write"
    )
    printing = "      - uses: attacker/permission-printer@v1"
    assert _scan(tmp_path, {WORKFLOW: template.format(gate=failing)}) == []
    assert [item["rule_id"] for item in _scan(tmp_path, {WORKFLOW: template.format(gate=printing)})] == [
        "SKY-D290"
    ]


def _doubling(levels):
    source = "'x'"
    for _ in range(levels):
        source = f"format('{{0}}{{0}}', {source})"
    return source


def test_folding_stops_at_its_size_budget(tmp_path):
    assert len(audits._foldings(expressions.parse_expression(_doubling(4)))) == 1
    assert audits._foldings(expressions.parse_expression(_doubling(49))) == []
    chain = "'a'"
    for _ in range(30):
        chain = f"toJSON({chain})"
    assert audits._foldings(expressions.parse_expression(chain)) == []
    deep = "toJSON(fromJSON('" + "[" * 600 + "]" * 600 + "'))"
    assert audits._foldings(expressions.parse_expression(deep)) == []

    workflow = (
        "name: big\non: push\npermissions:\n  contents: read\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        f"      - run: echo \"${{{{ {_doubling(49)} }}}}\"\n"
    )
    assert _scan(tmp_path, {WORKFLOW: workflow}) == []
