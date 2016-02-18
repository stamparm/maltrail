# Docker run

```
sudo su
docker build -t maltrail . && \
docker run -d --net=host --privileged -v /var/log/maltrail/:/var/log/maltrail/ maltrail && \
docker ps  # reporting interface: http://localhost:8338
```
