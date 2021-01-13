## Ubuntu/Debian

```sh
    export MALTRAIL_LOCAL=$(realpath ~/.local/share/maltrail)
    mkdir -p $MALTRAIL_LOCAL
    cd $MALTRAIL_LOCAL
    wget https://raw.githubusercontent.com/stamparm/maltrail/master/docker/Dockerfile
    wget https://raw.githubusercontent.com/stamparm/maltrail/master/maltrail.conf
    sudo su
    apt -qq -y install coreutils net-tools docker.io
    for dev in $(ifconfig | grep mtu | grep -Eo '^\w+'); do ifconfig $dev promisc; done
    mkdir -p /var/log/maltrail/
    docker build -t maltrail . && \
    docker run -d --name maltrail-docker --net host --privileged -v /var/log/maltrail/:/var/log/maltrail/ -v $MALTRAIL_LOCAL/maltrail.conf:/opt/maltrail/maltrail.conf maltrail
```
