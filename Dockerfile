FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt requirements-model.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY codeguard ./codeguard
COPY scripts ./scripts

# Optional prompt-injection model (~740 MB). Default image runs without it:
# the ai_model layer then switches itself off and every other layer works.
#   docker build --build-arg WITH_MODEL=1 -t codeguard .
ARG WITH_MODEL=0
RUN if [ "$WITH_MODEL" = "1" ]; then \
        pip install --no-cache-dir -r requirements-model.txt && python scripts/download_model.py; \
    fi

RUN useradd --create-home --uid 10001 codeguard && chown -R codeguard /app
USER codeguard

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["sh", "-c", "uvicorn codeguard.api.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WORKERS:-2}"]
