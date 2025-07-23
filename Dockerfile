FROM python:3
WORKDIR /opt/maltrail
ENV PYTHONWARNINGS=ignore
# Update OS

RUN apt-get update && apt-get upgrade -y

# Install dependencies
RUN apt-get install -y libpcap-dev cron
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Update trails daily
RUN touch /var/log/cron.log
RUN python /opt/maltrail/core/update.py

# Update trails daily
RUN echo '0 1 * * * /opt/maltrail/core/update.py' | crontab

# Expose server ports
EXPOSE 8337/udp
EXPOSE 8338/tcp

# Run server by default
CMD /opt/maltrail/server.py
