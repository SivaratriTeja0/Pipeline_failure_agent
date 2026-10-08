# Pipeline Failure Triage & Human-Approved Self-Healing Agent - API and UI image.
# The same image runs the API (default) or the Streamlit UI (see docker-compose.yml).
FROM python:3.12.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY actions ./actions
COPY adapters ./adapters
COPY agent ./agent
COPY api ./api
COPY core ./core
COPY database ./database
COPY demo ./demo
COPY evaluation ./evaluation
COPY frontend ./frontend
COPY notifications ./notifications
COPY security ./security
COPY tools ./tools

RUN useradd --create-home --uid 10001 triage && mkdir -p /data && chown triage /data
USER triage

# Safe defaults (Rule 6); override with an env file. Never bake credentials into the image.
ENV DEMO_MODE=true \
    AUTH_PROVIDER=demo \
    HEALING_ENABLED=false \
    HEALING_EXECUTION_MODE=DRY_RUN \
    DATABASE_URL=sqlite:////data/triage.db

EXPOSE 8000 8501
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
