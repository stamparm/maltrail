FROM debian:jessie

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y python-pcapy git curl schedtool \
    && git clone https://github.com/stamparm/maltrail.git /opt/maltrail \
    && python /opt/maltrail/core/update.py

WORKDIR /opt/maltrail

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN ln -s /usr/local/bin/docker-entrypoint.sh /

ENTRYPOINT ["/bin/bash", "/docker-entrypoint.sh"]
