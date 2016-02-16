FROM debian:jessie

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y python-pcapy git curl schedtool \
    && git clone https://github.com/stamparm/maltrail.git /root/maltrail \
    && python /root/maltrail/core/update.py

WORKDIR /root/maltrail

COPY run.sh /root/run.sh

ENTRYPOINT  ["/bin/bash", "/root/run.sh"]

