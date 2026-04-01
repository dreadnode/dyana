FROM python:3.14-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.19 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./

RUN uv sync --locked --no-dev --no-install-project

FROM python:3.14-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y libssl-dev curl ca-certificates
RUN curl -fsSL https://get.docker.com | sh

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

WORKDIR /app
COPY dyana ./dyana

ENTRYPOINT ["python", "-m", "dyana"]
