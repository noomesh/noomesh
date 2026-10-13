FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

WORKDIR /browser

# Vendor telemetry off (docs/security/telemetry.md), baked into the image so
# a container started outside compose carries it too; compose sets the same.
ENV HF_HUB_DISABLE_TELEMETRY=1 \
    DO_NOT_TRACK=1

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.115.* \
    uvicorn[standard]==0.32.* \
    pydantic==2.*

# Install Playwright browsers (Chromium only to save space)
RUN playwright install chromium

# Copy server code
COPY server.py /browser/server.py

# No host filesystem access
# Network: outbound HTTP/HTTPS only (controlled by Docker network)
# Resource limits applied by the container runner

EXPOSE 9222

ENV BROWSER_PORT=9222
ENV BROWSER_IDLE_TIMEOUT=300
ENV BROWSER_MAX_SESSION=600

CMD ["python", "/browser/server.py"]
