FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    miniupnpc \
    && rm -rf /var/lib/apt/lists/*

COPY Server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Server/server.py .

# The two operator tools that work on the DATABASE, which lives in this
# container's volume -- so they belong where the database is. Without them an
# operator on the docker deployment we actually recommend cannot answer the two
# questions that come up first: how many seats are in use, and how do I cut off
# the person who left. Both are read-only by default and refuse to act without
# --yes.
#
# subrosa_doctor.py is deliberately NOT here. It inspects the HOST: which
# address is really being listened on, whether nginx loaded the config it
# thinks it did, ufw, certificate expiry, the MTU clamp. Inside a container all
# of those belong to the container's own namespaces, so it would answer
# confidently and wrongly -- exactly the failure the healthcheck used to have
# (KL-25, and the 'reported healthy while the server was dead' note in
# docker-compose.yml). Run it on the host, where the answers mean something.
COPY Server/admin_users.py Server/admin_gen_codes.py .


EXPOSE 9000

CMD ["python", "server.py", "--dev"]
