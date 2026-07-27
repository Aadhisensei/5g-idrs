FROM python:3.11-slim

WORKDIR /app
COPY parsers/nas/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY parsers/nas/parser.py .

CMD ["python3", "parser.py"]
