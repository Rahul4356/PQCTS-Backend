# Dockerfile for FastAPI Backend
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python application
COPY app_modified.py .
COPY index.html .
COPY sw.js .

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.121.3 \
    uvicorn[standard]==0.38.0 \
    httpx==0.28.1 \
    sqlalchemy==2.0.44 \
    bcrypt==5.0.0 \
    pyjwt==2.9.0 \
    cryptography==43.0.3 \
    pydantic==2.12.4 \
    email-validator==2.3.0 \
    cffi==2.0.0

# Create directory for database
RUN mkdir -p /app/data

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:4000/api/health || exit 1

# Set environment variables
ENV QUANTUM_API_URL=http://quantum-service:3001
ENV DATABASE_URL=sqlite:///./data/qms_quantum.db

# Run the application
CMD ["python", "app_modified.py"]
