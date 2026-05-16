FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -e ".[all]" "mcp[cli]>=1.0.0"

ENV MCP_TRANSPORT=sse
ENV PORT=8080
# Set SKYLOS_MCP_TOKEN at runtime; network transports fail closed without it.
EXPOSE 8080

ENTRYPOINT ["python", "-u", "-m", "skylos_mcp.server"]
