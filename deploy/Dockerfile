FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    miniupnpc \
    && rm -rf /var/lib/apt/lists/*

COPY Server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Server/server.py .


EXPOSE 9000

CMD ["python", "server.py", "--dev"]
