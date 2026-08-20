FROM python:3.11-slim

# Не-root пользователь для безопасности
RUN useradd -r -s /bin/false beacon

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Директория для SQLite базы данных
RUN mkdir /data && chown beacon:beacon /data

USER beacon

VOLUME ["/data"]

ENV DB_PATH=/data/messages.db

EXPOSE 9000

# --dev: сервер без TLS (TLS терминируется на nginx снаружи)
CMD ["python", "server.py", "--dev"]
