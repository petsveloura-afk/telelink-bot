FROM python:3.12-slim

# Prevent .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

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

CMD ["python", "main.py"]