FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Proposal event logs AND the accounts file persist on the /data
# volume -- accounts.json defaults to ~/.quorum (container-local),
# which every recreate would wipe.
ENV QUORUM_DATA_DIR=/data/proposals
ENV QUORUM_ACCOUNTS=/data/accounts.json
ENV QUORUM_PORT=8000

CMD ["quorum-mcp-http"]
