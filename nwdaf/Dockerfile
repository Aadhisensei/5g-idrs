FROM python:3.11-slim

WORKDIR /app
COPY nwdaf/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY nwdaf/app.py .

EXPOSE 8090
CMD ["python3", "app.py"]
