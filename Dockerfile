FROM python:3.13-bookworm AS builder

RUN pip install poetry==1.8.3

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock README.md ./

RUN poetry install --no-root && rm -rf $POETRY_CACHE_DIR

FROM python:3.13-slim-bookworm AS runtime

# install requirements to use docker from within docker
RUN apt-get update && apt-get install -y libssl-dev curl ca-certificates
RUN curl -fsSL https://get.docker.com | sh


ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY dyana ./dyana

ENTRYPOINT ["python", "-m", "dyana"]