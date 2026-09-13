FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MONO_ENV=prod

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY index.html /static/index.html

EXPOSE 8000
# DATABASE_URL, MONO_JWT_SECRET, MONO_CORS_ORIGINS come from the platform env.
# Respect $PORT (Render injects it, default 10000); fall back to 8000 locally.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]
