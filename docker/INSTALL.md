# How-To (Ubuntu)

    sudo su
    apt -qq -y install coreutils net-tools docker.io
    if [ ! -f "../maltrail.conf" ]; then
        cd /opt
        git clone --depth=1 https://github.com/stamparm/maltrail.git
        cd /opt/maltrail/docker
    fi
    export MALTRAIL_CONF=$(realpath ../maltrail.conf)
    for dev in $(ifconfig | grep mtu | grep -Eo '^\w+'); do ifconfig $dev promisc; done
    mkdir -p /var/log/maltrail/
    docker build -t maltrail . && \
    docker run -d --name maltrail-docker --net host --privileged -v /var/log/maltrail/:/var/log/maltrail/ -v $MALTRAIL_CONF:/opt/maltrail/maltrail.conf maltrail  # Note: reporting interface http://localhost:8338
