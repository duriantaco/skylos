FROM golang:1.22 AS go-build

WORKDIR /src/skylos/engines/go

COPY skylos/engines/go/go.mod ./
COPY skylos/engines/go/cmd ./cmd
COPY skylos/engines/go/internal ./internal

RUN go build -o /out/skylos-go ./cmd/skylos-go

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY skylos ./skylos
COPY --from=go-build /out/skylos-go ./skylos/engines/go/skylos-go

RUN python -m pip install --upgrade pip build && \
    python -m build --wheel --outdir /dist && \
    python -m pip wheel --wheel-dir /wheelhouse /dist/*.whl

FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work

COPY --from=build /wheelhouse /tmp/wheelhouse

RUN python -m pip install --no-index --find-links=/tmp/wheelhouse skylos && \
    rm -rf /tmp/wheelhouse

ENTRYPOINT ["skylos"]
CMD ["--help"]
