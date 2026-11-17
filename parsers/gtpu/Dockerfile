FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY parsers/gtpu/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY parsers/gtpu/parser.py .
CMD ["python3", "parser.py"]
