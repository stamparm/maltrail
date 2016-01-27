# Docker run opts

```bash
docker build -t maltrail . && \
docker run -d --net=host --privileged -v /var/log/maltrail/:/var/log/maltrail/ maltrail
```
