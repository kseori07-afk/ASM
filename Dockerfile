# Dockerfile for ASM tool: includes Python, Nmap, Subfinder, Naabu, and Nuclei.
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    GOBIN=/usr/local/bin \
    PATH=/usr/local/bin:/root/go/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        golang-go \
        nmap \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

CMD ["python", "main.py"]
