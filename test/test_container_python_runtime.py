from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_supports_selectable_python_runtime():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "ARG PYTHON_VERSION=3.14" in dockerfile
    assert dockerfile.count("FROM python:${PYTHON_VERSION}-slim") == 2
    assert "SKYLOS_CONTAINER_PYTHON_VERSION=${PYTHON_VERSION}" in dockerfile


def test_docker_runtime_includes_native_go_engine():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "RUN go build -o /out/skylos-go ./cmd/skylos-go" in dockerfile
    assert "COPY --from=go-build /out/skylos-go /usr/local/bin/skylos-go" in dockerfile


def test_publish_workflow_pushes_versioned_python_runtime_tags():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in workflow
    assert 'DEFAULT_PYTHON_VERSION: "3.14"' in workflow
    assert '--build-arg "PYTHON_VERSION=${PYTHON_VERSION}"' in workflow
    assert '"${IMAGE_NAME}:${VERSION}-${runtime_tag}"' in workflow
    assert '"${IMAGE_NAME}:latest-${runtime_tag}"' in workflow
    assert 'if [[ "$PYTHON_VERSION" == "$DEFAULT_PYTHON_VERSION" ]]' in workflow
    assert "skylos:smoke doctor --format json" in workflow
    assert "json.load(sys.stdin)" in workflow


def test_ci_builds_oldest_and_default_python_runtime_images():
    workflow = (ROOT / ".github" / "workflows" / "tests.yaml").read_text(
        encoding="utf-8"
    )

    assert 'python-version: ["3.11", "3.14"]' in workflow
    assert '--build-arg "PYTHON_VERSION=${{ matrix.python-version }}"' in workflow
    assert "type CacheEntry[T = str] = dict[str, T]" in workflow
    assert "skylos:test doctor --format json" in workflow
    assert "json.load(sys.stdin)" in workflow
