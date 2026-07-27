FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY parsers/pfcp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY parsers/pfcp/parser.py .

CMD ["python3", "parser.py"]
