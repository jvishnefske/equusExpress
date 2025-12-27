.PHONY: test coverage lint clean install help

PYTHON ?= python3
PIP ?= pip
PYTEST ?= pytest
COVERAGE ?= coverage
FLAKE8 ?= flake8

help:
	@echo "Available targets:"
	@echo "  install   - Install package and dev dependencies"
	@echo "  test      - Run tests with pytest"
	@echo "  coverage  - Run tests with coverage and generate reports"
	@echo "  lint      - Run flake8 linter"
	@echo "  clean     - Remove build artifacts and cache files"

install:
	$(PIP) install -e .[dev]
	$(PIP) install pytest pytest-cov coverage flake8

test:
	$(PYTEST) tests/ -v

coverage:
	$(COVERAGE) run -m pytest tests/ -v
	$(COVERAGE) report -m
	$(COVERAGE) xml -o coverage.xml
	$(COVERAGE) html -d htmlcov

lint:
	$(FLAKE8) src/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
	$(FLAKE8) src/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf htmlcov/
	rm -rf __pycache__/
	rm -rf src/__pycache__/
	rm -rf tests/__pycache__/
	rm -rf .eggs/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.db" -delete 2>/dev/null || true
