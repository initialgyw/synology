FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/initialgyw/synology"
LABEL org.opencontainers.image.title="synology"
LABEL org.opencontainers.image.description="Synology NAS management CLI"
LABEL org.opencontainers.image.documentation="https://github.com/initialgyw/synology"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk add --no-cache git \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        cargo \
        libffi-dev \
        openssl-dev

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
    && apk del .build-deps

ENTRYPOINT ["syn-cli"]
