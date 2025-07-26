FROM python:3

# Workdir and metadata
WORKDIR /opt/maltrail

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS=ignore \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies, update apt packages, clear apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev cron tini && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements.txt separately to leverage Docker cache
COPY ../requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Copy the start script and make it executable
COPY docker/start.sh /opt/maltrail/start.sh
RUN chmod +x /opt/maltrail/start.sh

# Re-route log output from a file to stdout, also create log file for cron
RUN ln -sf /dev/stdout /var/log/maltrail.log && \
    ln -sf /dev/stdout /var/log/cron.log

# Initial update of trails
RUN python /opt/maltrail/core/update.py

# Update trails daily
RUN echo '0 1 * * * /opt/maltrail/core/update.py >> /var/log/cron.log 2>&1' | crontab

# Expose server ports
EXPOSE 8337/udp
EXPOSE 8338/tcp

# Set tini as entrypoint to handle cron and maltrail process
ENTRYPOINT ["/usr/bin/tini", "--"]

# Execute start.sh to start cron and maltrail
CMD ["/opt/maltrail/start.sh"]