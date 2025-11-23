# Dockerfile for Quantum Crypto Service (C with liboqs)
FROM ubuntu:22.04

# Avoid timezone prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs
RUN cd /tmp && \
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    cd / && rm -rf /tmp/liboqs

# Create app directory
WORKDIR /app

# Copy source files
COPY quantum_service.c quantum_crypto.c json_utils.c \
     quantum_crypto.h json_utils.h Makefile ./

# Build the quantum service
RUN make clean && make

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

# Run the service
CMD ["./quantum_service"]
