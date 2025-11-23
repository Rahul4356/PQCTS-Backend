#!/bin/bash
set -e

echo "=========================================="
echo "PQCTS Backend - Azure Startup Script"
echo "=========================================="
echo "Environment: ${ENVIRONMENT:-production}"
echo "Port: ${PORT:-8000}"
echo "Quantum Service Port: ${QUANTUM_SERVICE_PORT:-3001}"
echo "Database: ${DATABASE_URL:-sqlite:///./qms_quantum.db}"
echo "=========================================="

# Start the C Quantum Service in the background
echo "Starting Quantum Service on port ${QUANTUM_SERVICE_PORT:-3001}..."
cd /app/quantum_service_c
./quantum_service &
QUANTUM_PID=$!
echo "Quantum Service started with PID: $QUANTUM_PID"

# Wait for quantum service to be ready
echo "Waiting for Quantum Service to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:${QUANTUM_SERVICE_PORT:-3001}/api/health > /dev/null 2>&1; then
        echo "Quantum Service is ready!"
        break
    fi
    echo "Waiting... ($i/30)"
    sleep 2
done

# Start FastAPI with Gunicorn
cd /app
echo "Starting FastAPI application on port ${PORT:-8000}..."
exec gunicorn app_modified:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:${PORT:-8000} \
    --timeout 120 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    --log-level ${LOG_LEVEL:-info}
