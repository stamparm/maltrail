FROM debian:stable-slim

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y python python-pcapy git curl schedtool cron procps \
    && git clone --depth=1 https://github.com/stamparm/maltrail.git /opt/maltrail \
    && python /opt/maltrail/core/update.py

RUN touch /var/log/cron.log
RUN (crontab -l ; echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep server.py)" ]; then : ; else python /opt/maltrail/server.py -c /opt/maltrail/maltrail.conf; fi >> /var/log/cron.log') | crontab
RUN (crontab -l ; echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep sensor.py)" ]; then : ; else python /opt/maltrail/sensor.py -c /opt/maltrail/maltrail.conf; fi >> /var/log/cron.log') | crontab
RUN (crontab -l ; echo '0 1 * * * cd /opt/maltrail && git pull') | crontab
RUN (crontab -l ; echo '2 1 * * * /usr/bin/pkill -f maltrail') | crontab

CMD bash -c "python /opt/maltrail/server.py &" && bash -c "python /opt/maltrail/sensor.py &" && cron && tail -f /var/log/cron.log
