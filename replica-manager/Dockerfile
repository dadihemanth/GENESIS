FROM python:3.11-slim

# Install docker CLI for Docker-in-Docker spawning
RUN apt-get update && apt-get install -y docker.io curl && rm -rf /var/lib/apt/lists/*
# Install docker compose plugin
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -SL "https://github.com/docker/compose/releases/download/v2.29.2/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 3701
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3701"]
