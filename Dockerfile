FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    miniupnpc=2.2.3-1 \
    && rm -rf /var/lib/apt/lists/*

COPY ForEXP/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ForEXP/server.py .

ENV SUBROSA_HOST=0.0.0.0
ENV SUBROSA_PORT=9000

EXPOSE 9000

CMD ["python", "server.py", "--dev"]
