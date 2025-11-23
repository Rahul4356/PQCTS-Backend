# Makefile for Quantum Crypto Service C Implementation

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -I/usr/local/include -I/opt/homebrew/opt/openssl@3/include -I/usr/include
LDFLAGS = -L/usr/local/lib -L/opt/homebrew/opt/openssl@3/lib -L/usr/lib
LIBS = -loqs -lssl -lcrypto -lpthread -lm

# Source files
SRCS = quantum_service.c quantum_crypto.c json_utils.c
OBJS = $(SRCS:.c=.o)
TARGET = quantum_service

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)
	@echo "✅ Build complete: $(TARGET)"

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "✅ Cleaned build files"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev cmake ninja-build git
	@echo "Building and installing liboqs..."
	cd /tmp && \
	git clone https://github.com/open-quantum-safe/liboqs.git && \
	cd liboqs && \
	mkdir build && cd build && \
	cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
	ninja && \
	sudo ninja install && \
	sudo ldconfig
	@echo "✅ Dependencies installed"

# Run the service
run: $(TARGET)
	@echo "Starting Quantum Crypto Service..."
	./$(TARGET)

# Run in background
run-background: $(TARGET)
	@echo "Starting Quantum Crypto Service in background..."
	nohup ./$(TARGET) > quantum_service.log 2>&1 &
	@echo "✅ Service started in background (PID: $$!)"

# Stop the service
stop:
	@pkill -f quantum_service || true
	@echo "✅ Service stopped"

# Check if service is running
status:
	@if pgrep -f quantum_service > /dev/null; then \
		echo "✅ Service is running"; \
		echo "PID: $$(pgrep -f quantum_service)"; \
	else \
		echo "❌ Service is not running"; \
	fi

# Test the service
test:
	@echo "Testing service endpoints..."
	@curl -s http://localhost:3001/api/health | python3 -m json.tool || echo "❌ Service not responding"

# Development build with debug symbols
debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)
	@echo "✅ Debug build complete"

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRCS)
	@echo "✅ Analysis complete"

# Format code
format:
	@echo "Formatting code..."
	clang-format -i $(SRCS) *.h
	@echo "✅ Code formatted"

# Help
help:
	@echo "Quantum Crypto Service - C Implementation"
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build the service"
	@echo "  make clean        - Clean build files"
	@echo "  make install-deps - Install dependencies (requires sudo)"
	@echo "  make run          - Build and run the service"
	@echo "  make run-background - Run service in background"
	@echo "  make stop         - Stop the service"
	@echo "  make status       - Check service status"
	@echo "  make test         - Test service endpoints"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make analyze      - Run static analysis"
	@echo "  make format       - Format source code"
	@echo "  make help         - Show this help message"

.PHONY: all clean install-deps run run-background stop status test debug analyze format help