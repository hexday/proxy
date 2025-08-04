FROM python:3.11-alpine

LABEL maintainer="MTProxy Team"
LABEL version="3.0"
LABEL description="Advanced MTProto Proxy Manager"

# Install system dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    sqlite-dev \
    curl \
    wget

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY mtproxy_manager.py .
COPY quick_setup.sh .

# Create necessary directories
RUN mkdir -p data logs cache config backups

# Create non-root user
RUN adduser -D -s /bin/sh mtproxy && \
    chown -R mtproxy:mtproxy /app

# Switch to non-root user
USER mtproxy

# Expose ports (proxy ports + web interface)
EXPOSE 8080-8180

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python mtproxy_manager.py status || exit 1

# Default command
CMD ["python", "mtproxy_manager.py", "run-all"]
