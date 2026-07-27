FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
COPY parsers/sbi_http2/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY parsers/sbi_http2/parser.py .

CMD ["python3", "parser.py"]
