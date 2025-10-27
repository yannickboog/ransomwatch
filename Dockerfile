FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt pyproject.toml ./
COPY ransomwatch ./ransomwatch

RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .

FROM python:3.12-slim

LABEL maintainer="security@yannick.xyz"
LABEL description="Ransomware Intelligence Tool"
LABEL version="1.2.3"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -r ransomwatch && \
    useradd -r -g ransomwatch -s /sbin/nologin ransomwatch

WORKDIR /app

COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

USER ransomwatch

ENTRYPOINT ["ransomwatch"]
CMD ["--help"]
