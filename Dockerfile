# Use Python base image
FROM python:3.10-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies, including Git
RUN apt-get update && apt-get install -y \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy project files into the container
COPY . /app

# Add /app to PYTHONPATH
ENV PYTHONPATH=/app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask default port
EXPOSE 5000

# Define the default command to run the app
CMD ["python", "app/app.py"]
