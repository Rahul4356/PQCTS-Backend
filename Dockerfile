# Multi-stage Dockerfile for PQCTS Backend
# Stage 1: Build liboqs and C quantum service
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs
WORKDIR /tmp
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        .. && \
    ninja && \
    ninja install && \
    ldconfig

# Copy C quantum service source
WORKDIR /app/quantum_service_c
COPY quantum_service_c/ .

# Build C quantum service
RUN make clean && make

# Stage 2: Runtime image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    QUANTUM_SERVICE_PORT=3001

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    libssl3 \
    ca-certificates \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs from builder
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

# Create app directory
WORKDIR /app

# Copy application files
COPY requirements.txt .
COPY app_modified.py .
COPY build_and_run.sh .
COPY sw.js .
COPY *.html . 2>/dev/null || true

# Copy C quantum service binary from builder
COPY --from=builder /app/quantum_service_c/quantum_service /app/quantum_service_c/

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Create supervisor configuration
RUN mkdir -p /var/log/supervisor
COPY <<EOF /etc/supervisor/conf.d/supervisord.conf
[supervisord]
nodaemon=true
user=root
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:quantum_service]
command=/app/quantum_service_c/quantum_service
directory=/app/quantum_service_c
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/quantum_service.err.log
stdout_logfile=/var/log/supervisor/quantum_service.out.log
environment=LD_LIBRARY_PATH="/usr/local/lib"

[program:fastapi]
command=gunicorn app_modified:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:%(ENV_PORT)s --timeout 120 --access-logfile - --error-logfile -
directory=/app
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/fastapi.err.log
stdout_logfile=/var/log/supervisor/fastapi.out.log
environment=QUANTUM_API_URL="http://localhost:%(ENV_QUANTUM_SERVICE_PORT)s"
EOF

# Create startup script
COPY <<'EOF' /app/startup.sh
#!/bin/bash
set -e

echo "=========================================="
echo "PQCTS Backend - Starting Services"
echo "=========================================="
echo "FastAPI Port: ${PORT:-8000}"
echo "Quantum Service Port: ${QUANTUM_SERVICE_PORT:-3001}"
echo "Database: ${DATABASE_URL:-sqlite:///./qms_quantum.db}"
echo "=========================================="

# Start supervisor
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
EOF

RUN chmod +x /app/startup.sh

# Expose ports
EXPOSE 8000 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import httpx; httpx.get('http://localhost:${PORT:-8000}/api/health', timeout=5.0)" || exit 1

# Run startup script
CMD ["/app/startup.sh"]
