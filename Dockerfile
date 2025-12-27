FROM python:3.12 AS builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN useradd --create-home --shell /bin/bash app

# Set work directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install Python dependencies and the package
RUN pip install --upgrade uv && \
    uv build


# Stage 2: Create the final runtime image
FROM python:3.12-slim-bookworm AS runner

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /home/appuser -m appuser

# Switch to the user and set working directory
USER appuser
WORKDIR /home/appuser

COPY --from=builder /app/dist/*.whl ./
RUN pip install --user ./*.whl
EXPOSE 8000

# Add ~/.local/bin to PATH for the appuser
ENV PATH="/home/appuser/.local/bin:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD httpx -f http://localhost:8000/health || exit 1

# Start the application
CMD ["uvicorn", "equus_express.server:app", "--host", "0.0.0.0", "--port", "8000"]
