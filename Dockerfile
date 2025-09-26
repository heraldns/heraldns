FROM python:3.11-slim

# Install Kerberos client tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        krb5-user \
        libkrb5-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    docker \
    dnspython \
    gssapi

# Copy the main script
COPY heraldns.py /app/heraldns.py
RUN chmod +x /app/heraldns.py

WORKDIR /app

# Run the sync script
CMD ["python", "-u", "/app/heraldns.py"]
