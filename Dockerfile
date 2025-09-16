# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Install system dependencies in a single layer to avoid read-only issues
RUN apt-get update && apt-get install -y --no-install-recommends \
    liboqs-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Your app's start command
CMD ["uvicorn", "module2:app", "--host", "0.0.0.0", "--port", "$PORT"]
