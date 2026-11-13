# example-addon image. The image's USER must be the uid resources.json
# declares (1000): the launcher hands the delivered files to that uid, 0400.
# Pinned by digest: an image is executable code, so name exactly the bytes
# you build on. HUB_MIRROR defaults to the project's public mirror of Docker
# Hub; --build-arg HUB_MIRROR=docker.io pulls the same digest direct.
ARG HUB_MIRROR=ghcr.io/noomesh/mirror
FROM ${HUB_MIRROR}/library/python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN pip install --no-cache-dir "psycopg[binary]==3.2.9" \
 && useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin addon
COPY app/server.py /app/server.py
USER 1000
EXPOSE 8090
ENTRYPOINT ["python3", "/app/server.py"]
