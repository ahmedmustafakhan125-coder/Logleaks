FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy the build configuration
COPY pyproject.toml /app/

# Copy the application code
COPY caredesk /app/caredesk/

# Install the package
RUN pip install --no-cache-dir .

# Expose port 8080 for fly.io
EXPOSE 8080

# Run the FastAPI app
CMD ["uvicorn", "caredesk.app:app", "--host", "0.0.0.0", "--port", "8080"]
