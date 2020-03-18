# How-To (Ubuntu)

    sudo su
    apt -qq -y install coreutils net-tools docker.io
    export MALTRAIL_CONF=$(realpath ../maltrail.conf)
    if [ ! -f "$MALTRAIL_CONF" ]; then
        cd /opt
        git clone --depth=1 https://github.com/stamparm/maltrail.git
        cd /opt/maltrail/docker
        export MALTRAIL_CONF=$(realpath ../maltrail.conf)
    fi
    for dev in $(ifconfig | grep eth | cut -d " " -f 1); do ifconfig $dev promisc; done
    mkdir -p /var/log/maltrail/
    docker build -t maltrail . && \
    docker run -d --name maltrail-docker --net host --privileged -v /var/log/maltrail/:/var/log/maltrail/ -v $MALTRAIL_CONF:/opt/maltrail/maltrail.conf maltrail  # Note: reporting interface http://localhost:8338
