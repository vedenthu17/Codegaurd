FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY codeguard ./codeguard

RUN useradd --create-home --uid 10001 codeguard
USER codeguard

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["sh", "-c", "uvicorn codeguard.api.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WORKERS:-2}"]
