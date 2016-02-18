# Docker run

```
sudo su
apt-get -qq install realpath
export MALTRAIL_CONF=$(realpath ../maltrail.conf)
for dev in $(ifconfig | grep eth | cut -d " " -f 1); do ifconfig $dev promisc; done
docker build -t maltrail . && \
docker run -d --net=host --privileged -v /var/log/maltrail/:/var/log/maltrail/ -v $MALTRAIL_CONF:/root/maltrail/maltrail.conf maltrail && \
docker ps  # reporting interface: http://localhost:8338
```
