#!/bin/bash

# Build and Run Script for Quantum Messaging System - macOS Version

echo "=================================================="
echo "Quantum Messaging System - C Backend Setup (macOS)"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is in use
port_in_use() {
    lsof -i:$1 >/dev/null 2>&1
}

echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check for required commands
if ! command_exists gcc; then
    echo -e "${RED}Error: gcc not found. Install with: sudo apt-get install build-essential${NC}"
    exit 1
fi

if ! command_exists python3; then
    echo -e "${RED}Error: python3 not found. Install with: sudo apt-get install python3${NC}"
    exit 1
fi

if ! command_exists pip3; then
    echo -e "${RED}Error: pip3 not found. Install with: sudo apt-get install python3-pip${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites checked${NC}"

# Check if liboqs is installed
echo -e "${YELLOW}Checking for liboqs...${NC}"
if ! ldconfig -p | grep -q liboqs; then
    echo -e "${RED}Warning: liboqs not found in system libraries${NC}"
    echo "You may need to install it first:"
    echo "  cd /tmp && git clone https://github.com/open-quantum-safe/liboqs.git"
    echo "  cd liboqs && mkdir build && cd build"
    echo "  cmake -GNinja .. && ninja && sudo ninja install"
    echo "  sudo ldconfig"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✓ liboqs found${NC}"
fi

# Build C service
echo -e "${YELLOW}Building C quantum service...${NC}"
cd quantum_service_c

if make clean && make; then
    echo -e "${GREEN}✓ C service built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build C service${NC}"
    exit 1
fi

cd ..

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip3 install -q fastapi uvicorn httpx sqlalchemy bcrypt pyjwt cryptography pydantic 2>/dev/null
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Check if ports are available
echo -e "${YELLOW}Checking ports...${NC}"

if port_in_use 3001; then
    echo -e "${YELLOW}Port 3001 is in use. Stopping existing service...${NC}"
    pkill -f quantum_service 2>/dev/null
    sleep 1
fi

if port_in_use 4000; then
    echo -e "${YELLOW}Port 4000 is in use. Stopping existing FastAPI service...${NC}"
    pkill -f "uvicorn.*4000" 2>/dev/null
    pkill -f "app_modified.py" 2>/dev/null
    sleep 1
fi

echo -e "${GREEN}✓ Ports are available${NC}"

# Start services
echo ""
echo "=================================================="
echo "Starting Services"
echo "=================================================="

# Start C quantum service in background
echo -e "${YELLOW}Starting C quantum service on port 3001...${NC}"

# Use nohup to properly detach the process on macOS
(cd quantum_service_c && nohup ./quantum_service > quantum_service.log 2>&1 &)
C_PID=$!

# Give it more time to start
sleep 3

# Check if C service started
if ps -p $C_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ C quantum service started (PID: $C_PID)${NC}"
else
    echo -e "${RED}✗ Failed to start C quantum service${NC}"
    echo "Checking for running process..."
    ps aux | grep quantum_service | grep -v grep
    if [ -f quantum_service_c/quantum_service.log ]; then
        echo "Error log:"
        tail -20 quantum_service_c/quantum_service.log
    fi
    exit 1
fi

# Test C service
echo -e "${YELLOW}Testing C service...${NC}"
if curl -s http://localhost:3001/api/health >/dev/null 2>&1; then
    echo -e "${GREEN}✓ C service is responding${NC}"
else
    echo -e "${YELLOW}⚠ C service may still be starting...${NC}"
    sleep 2
    if curl -s http://localhost:3001/api/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ C service is now responding${NC}"
    else
        echo -e "${RED}✗ C service is not responding${NC}"
        echo "Process status:"
        ps aux | grep quantum_service | grep -v grep
        exit 1
    fi
fi

# Start FastAPI backend
echo -e "${YELLOW}Starting FastAPI backend on port 4000...${NC}"
nohup ./.venv/bin/python app_modified.py > fastapi.log 2>&1 &
FASTAPI_PID=$!
sleep 4

# Check if FastAPI started
if ps -p $FASTAPI_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ FastAPI backend started (PID: $FASTAPI_PID)${NC}"
else
    echo -e "${RED}✗ Failed to start FastAPI backend${NC}"
    if [ -f fastapi.log ]; then
        echo "FastAPI log:"
        tail -20 fastapi.log
    fi
    kill $C_PID 2>/dev/null
    exit 1
fi

echo ""
echo "=================================================="
echo -e "${GREEN}✅ System Running Successfully!${NC}"
echo "=================================================="
echo ""
echo "Services running:"
echo "  • C Quantum Service: http://localhost:3001 (PID: $C_PID)"
echo "  • FastAPI Backend: http://localhost:4000 (PID: $FASTAPI_PID)"
echo ""
echo "Access the web interface at:"
echo -e "${GREEN}  http://localhost:4000${NC}"
echo ""
echo "API Documentation:"
echo "  • http://localhost:4000/docs (FastAPI)"
echo ""
echo "To stop all services, run:"
echo "  kill $C_PID $FASTAPI_PID"
echo "  # Or use: pkill -f quantum_service && pkill -f app_modified"
echo ""
echo "Logs:"
echo "  • C Service: quantum_service_c/quantum_service.log"
echo "  • FastAPI: fastapi.log"
echo ""
echo "Press Ctrl+C to stop all services..."
echo "=================================================="

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping services...${NC}"
    kill $C_PID 2>/dev/null
    kill $FASTAPI_PID 2>/dev/null
    pkill -f quantum_service 2>/dev/null
    pkill -f app_modified 2>/dev/null
    echo -e "${GREEN}✓ Services stopped${NC}"
    exit 0
}

# Set trap to cleanup on Ctrl+C
trap cleanup INT

# Keep script running
while true; do
    sleep 5
    # Check if services are still running
    if ! ps -p $C_PID > /dev/null 2>&1; then
        echo -e "${RED}C service stopped unexpectedly${NC}"
        cleanup
    fi
    if ! ps -p $FASTAPI_PID > /dev/null 2>&1; then
        echo -e "${RED}FastAPI service stopped unexpectedly${NC}"
        cleanup
    fi
done