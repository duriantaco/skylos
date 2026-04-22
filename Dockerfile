FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

COPY pyproject.toml README.md LICENSE ./
COPY skylos ./skylos

RUN python -m pip install --upgrade pip build && \
    python -m build --wheel --outdir /dist

FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work

COPY --from=build /dist/*.whl /tmp/dist/

RUN python -m pip install /tmp/dist/*.whl && \
    rm -rf /tmp/dist

ENTRYPOINT ["skylos"]
CMD ["--help"]
