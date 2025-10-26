# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install dependencies (use pyproject.toml or requirements.txt)
RUN pip install --no-cache-dir -r requirements.txt || true
RUN pip install --no-cache-dir .

# Expose the server port (if using FastAPI/uvicorn)
EXPOSE 8080

# Start the MCP server
CMD ["python", "main.py"]
