FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    pip install --no-cache-dir -e ".[all]" "mcp[cli]>=1.0.0" && \
    apt-get purge -y --auto-remove gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

ENV MCP_TRANSPORT=sse
ENV MCP_BIND=0.0.0.0
ENV PORT=8080
# Set SKYLOS_MCP_TOKEN at runtime; network transports fail closed without it.
EXPOSE 8080

ENTRYPOINT ["python", "-u", "-m", "skylos_mcp.server"]
