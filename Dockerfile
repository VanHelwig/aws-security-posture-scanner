FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/home/scanner

WORKDIR /app

RUN useradd \
    --create-home \
    --home-dir /home/scanner \
    --shell /usr/sbin/nologin \
    scanner

COPY pyproject.toml README.md ./
COPY app ./app

RUN pip install --no-cache-dir .

RUN chown -R scanner:scanner /app

USER scanner

ENTRYPOINT ["python", "-m", "app.main"]