# Quantum Messaging System - Backend API Server

This is the **backend-only API server** for the Quantum Messaging System (PQCTS). The frontend application is hosted in a separate repository and connects to this backend via REST APIs and WebSockets.

This project implements a high-performance C-based quantum cryptography service integrated with a FastAPI backend, providing quantum-resistant encryption for secure messaging.

## Architecture

This backend server consists of two main components:

1. **C Quantum Service** (`quantum_service_c/`):
   - `quantum_service.c` - HTTP server and API endpoints
   - `quantum_crypto.c` - Quantum cryptography operations using liboqs
   - `json_utils.c` - JSON parsing and generation utilities
   - Runs on port 3001 (internal)

2. **Python FastAPI Backend** (`app_modified.py`):
   - REST API endpoints for authentication, messaging, and session management
   - WebSocket support for real-time communication
   - Communicates with C quantum service via HTTP
   - Runs on port 8000 (configurable via PORT env var)

3. **Frontend Application** (separate repository):
   - Connects to this backend via REST APIs and WebSockets
   - Configure CORS_ORIGINS environment variable to allow your frontend domain

## Prerequisites

- Ubuntu/Debian Linux (or compatible)
- GCC compiler
- OpenSSL development libraries
- liboqs (Open Quantum Safe library)
- Python 3.8+ with FastAPI

## Installation

### 1. Install System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev cmake ninja-build git python3-pip
```

### 2. Build and Install liboqs
```bash
cd /tmp
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig
```

### 3. Build the C Quantum Service
```bash
cd quantum_service_c
make clean
make
```

### 4. Install Python Dependencies
```bash
pip install fastapi uvicorn httpx sqlalchemy bcrypt pyjwt cryptography pydantic
```

## Running the System

### 1. Start the C Quantum Service
```bash
cd quantum_service_c
./quantum_service
# Or run in background:
make run-background
```

The C service will start on port 3001 and display:
```
================================================================================
QUANTUM CRYPTO SERVICE - C IMPLEMENTATION - v3.0.0
================================================================================
✅ RUNNING WITH REAL QUANTUM CRYPTOGRAPHY
✅ liboqs enabled
================================================================================
```

### 2. Start the FastAPI Backend

In a new terminal:
```bash
python3 app_modified.py
```

The FastAPI service will start on port 4000.

### 3. Access the Web Interface

Open your browser and navigate to:
```
http://localhost:4000
```

You'll see the index.html frontend, which will work seamlessly with the new C backend.

## API Endpoints (C Service)

The C quantum service implements the following endpoints:

- `POST /api/quantum/keygen` - Generate quantum-resistant keys
- `POST /api/quantum/encapsulate` - ML-KEM-768 encapsulation
- `POST /api/quantum/decapsulate` - ML-KEM-768 decapsulation
- `POST /api/quantum/encrypt` - AES-256-GCM encryption
- `POST /api/quantum/decrypt` - AES-256-GCM decryption
- `GET /api/quantum/info` - Service information
- `GET /api/health` - Health check

## Performance Benefits

The C implementation provides:
- **Faster execution**: Native C code is significantly faster than Python
- **Lower memory usage**: More efficient memory management
- **Better concurrency**: Threading model optimized for high throughput
- **Direct liboqs integration**: No Python wrapper overhead

## Testing

### Test C Service Health
```bash
curl http://localhost:3001/api/health | python3 -m json.tool
```

### Test Key Generation
```bash
curl -X POST http://localhost:3001/api/quantum/keygen \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test_user","key_type":"all"}' | python3 -m json.tool
```

### Test Full System
1. Open http://localhost:4000 in your browser
2. Register two users
3. Exchange messages between them

## Makefile Commands

The C service includes a comprehensive Makefile:
```bash
make              # Build the service
make clean        # Clean build files
make run          # Build and run
make run-background # Run in background
make stop         # Stop the service
make status       # Check service status
make test         # Test endpoints
make debug        # Debug build
make help         # Show all commands
```

## Limitations

Current implementation limitations (for simplicity):
1. **Wrap-and-sign protocol**: Not fully implemented in C version. The app uses placeholder signatures.
2. **Session persistence**: Sessions are stored in memory and lost on restart.
3. **WebSocket support**: Not implemented in C service (HTTP only).

These can be implemented in the C backend for production use.

## Extending the C Service

To add new endpoints:
1. Add handler function in `quantum_service.c`
2. Add route in the main request dispatcher
3. Implement crypto operations in `quantum_crypto.c`
4. Rebuild with `make`

## Security Notes

- The C implementation uses real quantum-resistant algorithms (ML-KEM-768, Falcon-512)
- ECDSA-P256 for classical cryptography
- AES-256-GCM for symmetric encryption
- All cryptographic operations use industry-standard libraries (liboqs, OpenSSL)

## Troubleshooting

### liboqs not found
```bash
# Ensure library path is set
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
sudo ldconfig
```

### Port already in use
```bash
# Kill existing process
make stop
# Or manually:
sudo lsof -i :3001
kill -9 <PID>
```

### Build errors
```bash
# Check dependencies
pkg-config --libs openssl
pkg-config --cflags openssl
# Reinstall if needed
sudo apt-get install libssl-dev
```

## Azure Deployment

This backend is **ready for Azure deployment**. See the detailed deployment guides:

- **[AZURE_READY.md](AZURE_READY.md)** - Quick start guide and checklist
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide with all options

### Quick Deploy to Azure

```bash
# Using Docker Compose (local testing)
docker-compose up --build

# Deploy to Azure Container Apps
az deployment group create \
  --resource-group pqcts-rg \
  --template-file azure-deploy.bicep \
  --parameters \
    containerImage=your-image:latest \
    jwtSecret=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

## Connecting Your Frontend

### CORS Configuration

Configure the `CORS_ORIGINS` environment variable to allow your frontend domain:

```bash
# Development (allows all origins)
CORS_ORIGINS=*

# Production (specific domains only)
CORS_ORIGINS=https://your-frontend.com,https://www.your-frontend.com
```

### Frontend API Configuration

Point your frontend to this backend:

```javascript
// In your frontend config
const API_BASE_URL = 'https://your-backend.azurecontainerapps.io';
const WS_URL = 'wss://your-backend.azurecontainerapps.io';
```

### Available API Endpoints

- **Authentication:** `/api/register`, `/api/login`, `/api/logout`
- **Key Exchange:** `/api/exchange/request`, `/api/exchange/respond`
- **Messaging:** `/api/messages/send`, `/api/messages/session/{session_id}`
- **Sessions:** `/api/sessions/active`, `/api/sessions/{session_id}/terminate`
- **WebSocket:** `/ws/{username}`
- **Utilities:** `/api/health`, `/api/users/available`, `/api/stats`

See `/docs` endpoint for complete API documentation.

## License

This implementation maintains compatibility with the original Python service while providing improved performance through native C code.