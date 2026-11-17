FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app
COPY nwdaf/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY nwdaf ./nwdaf

EXPOSE 8090
CMD ["python3", "-m", "nwdaf.app"]
