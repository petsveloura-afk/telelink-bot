FROM python:3.12-slim

# Prevent .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=10000

WORKDIR /app

# Install system dependencies (minimal layer — cached separately)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer — only rebuilds when requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create runtime directories that the bot writes to
RUN mkdir -p /app/logs /app/data

# Drop to non-root user for security
RUN addgroup --system botgroup && adduser --system --ingroup botgroup botuser
RUN chown -R botuser:botgroup /app
USER botuser

EXPOSE 10000

# Container-level health probe (the bot serves /health on $PORT)
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD python -c 'import os,urllib.request as u;u.urlopen("http://127.0.0.1:%s/health"%os.getenv("PORT","10000"),timeout=4)' || exit 1

CMD ["python", "main.py"]
