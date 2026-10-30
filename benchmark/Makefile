.PHONY: help setup run clean clean-all install-deps check-deps benchmark quick

PYTHON := python3
ITERATIONS := 10

help:
	@echo "Hash-Based Signature Benchmark Suite"
	@echo "===================================="
	@echo ""
	@echo "Available targets:"
	@echo "  make setup         - Clone and build both implementations"
	@echo "  make run          - Run benchmark with default iterations (10)"
	@echo "  make benchmark    - Alias for run"
	@echo "  make quick        - Run quick benchmark (5 iterations)"
	@echo "  make full         - Run full benchmark (50 iterations)"
	@echo "  make check-deps   - Check if required dependencies are installed"
	@echo "  make install-deps - Install Python dependencies (if any)"
	@echo "  make clean        - Remove generated benchmark data"
	@echo "  make clean-all    - Remove everything including cloned repos"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make setup && make run"
	@echo "  make benchmark ITERATIONS=20"

check-deps:
	@echo "Checking dependencies..."
	@command -v $(PYTHON) >/dev/null 2>&1 || { echo "Python 3 is required but not installed."; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "Git is required but not installed."; exit 1; }
	@command -v cargo >/dev/null 2>&1 || { echo "Rust (cargo) is required but not installed. Install from https://rustup.rs/"; exit 1; }
	@command -v zig >/dev/null 2>&1 || { echo "Zig compiler is required but not installed. Install from https://ziglang.org/download/"; exit 1; }
	@echo "✓ All dependencies are installed"

install-deps:
	@echo "No additional Python dependencies required"

setup: check-deps
	@echo "Setup will be handled automatically by benchmark.py"
	@echo "Run 'make run' to start the benchmark"

run: check-deps
	@$(PYTHON) benchmark.py $(ITERATIONS)

benchmark: run

quick: check-deps
	@$(PYTHON) benchmark.py 5

one: check-deps
	@$(PYTHON) benchmark.py 1

full: check-deps
	@$(PYTHON) benchmark.py 50

clean:
	@echo "Cleaning benchmark output..."
	@rm -rf benchmark_output/
	@echo "✓ Cleaned benchmark data"

clean-all: clean
	@echo "Removing cloned repositories..."
	@rm -rf hash-sig/ hash-zig/
	@echo "✓ Removed all cloned repositories"

# Development targets
.PHONY: test lint format

test:
	@echo "Running tests..."
	@$(PYTHON) -m pytest tests/ -v

lint:
	@echo "Running linter..."
	@$(PYTHON) -m pylint benchmark.py

format:
	@echo "Formatting code..."
	@$(PYTHON) -m black benchmark.py

# Info targets
.PHONY: info version

info:
	@echo "System Information:"
	@echo "  Python: $$($(PYTHON) --version)"
	@echo "  Git: $$(git --version)"
	@echo "  Zig: $$(zig version 2>/dev/null || echo 'not installed')"
	@echo "  GCC: $$(gcc --version 2>/dev/null | head -n1 || echo 'not installed')"
	@echo "  Clang: $$(clang --version 2>/dev/null | head -n1 || echo 'not installed')"

version:
	@echo "Hash-Based Signature Benchmark Suite v1.0.0"
