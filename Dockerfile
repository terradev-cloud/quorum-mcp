FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Proposal event logs persist in a volume mounted at /data
ENV QUORUM_DATA_DIR=/data/proposals
ENV QUORUM_PORT=8000

CMD ["quorum-mcp-http"]
