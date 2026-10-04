FROM python:3.12-slim

WORKDIR /app

# Install system utilities for network scanning and packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    net-tools \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

EXPOSE 8000

# Run with host network mode for packet sniffing:
# docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW -p 8000:8000 netmeter
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
