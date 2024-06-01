## Ubuntu/Debian

```sh
    #!/bin/bash
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
    docker run -d --name maltrail-docker --privileged -p 8337:8337/udp -p 8338:8338 -v /var/log/maltrail/:/var/log/maltrail/ -v $(pwd)/maltrail.conf:/opt/maltrail/maltrail.conf:ro maltrail
```
