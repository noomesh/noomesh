# example-addon image. The image's USER must be the uid resources.json
# declares (1000): the launcher hands the delivered files to that uid, 0400.
FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.9" \
 && useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin addon
COPY app/server.py /app/server.py
USER 1000
EXPOSE 8090
ENTRYPOINT ["python3", "/app/server.py"]
