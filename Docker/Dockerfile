FROM debian:jessie

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y python-pcapy git curl schedtool \
    && git clone https://github.com/stamparm/maltrail.git 

WORKDIR /maltrail

COPY run.sh /run.sh

ENTRYPOINT  ["/bin/bash", "/run.sh"]

