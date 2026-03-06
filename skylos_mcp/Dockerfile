FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir skylos "mcp[cli]>=1.0.0"

ENTRYPOINT ["python", "-u", "-m", "skylos_mcp.server"]
