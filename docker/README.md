# Docker

To build this image, please change your build context to the maltrail repo root. If you are in this very directory, please do so: 
```
cd ..
docker build -f docker/Dockerfile -t maltrail .
```
Otherwise you will get some `file not found` errors. 