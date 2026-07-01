###############
# build image #
###############
FROM python:3.14-trixie AS build

# Other environment variables
ENV VENV="/opt/maltrail"
ENV PATH="${VENV}/bin:${PATH}"

# Pypcap-ng
RUN --mount=type=cache,target=/var/lib/apt apt -qq update && apt -y install libpcap-dev

# Virtualenv
RUN python -m venv $VENV

# Switch to working directory
WORKDIR ${VENV}

# Pip
COPY requirements.txt ./
RUN pip install -r requirements.txt

####################
# production image #
####################
FROM python:3.14-slim-trixie

# Env
ENV VENV="/opt/maltrail"
ENV PATH="${VENV}/bin:${PATH}"

# Workdir
WORKDIR ${VENV}

# Copy maltrail dependencies from build container
COPY --from=build ${VENV} ${VENV}

# Copy required maltrail directories and files
COPY core core
COPY html html
COPY misc misc
COPY plugins plugins
COPY thirdparty thirdparty
COPY trails trails
COPY maltrail.conf maltrail.conf

COPY sensor.py sensor.py
COPY server.py server.py

# Install required packages
RUN --mount=type=cache,target=/var/lib/apt apt -qq update && apt -y install libpcap0.8t64 xz-utils

# S6 overlay
ARG S6_OVERLAY_VERSION=3.2.3.0

ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz

# Copy S6 service definitions
COPY docker/etc/services.d /etc/services.d

# Initial update of trails
#RUN python core/update.py

# To keep this compatible with existing docker-compose instructions
RUN ln -sf /opt/maltrail/server.py /usr/local/bin/server.py \
    && ln -sf /opt/maltrail/sensor.py /usr/local/bin/sensor.py \
    && chmod +x sensor.py server.py

# Places where maltrail writes
VOLUME /var/log/maltrail
VOLUME /root/.maltrail 

# Run a very simple test if everything works
RUN python server.py --version
RUN python sensor.py --version

# Expose server ports
EXPOSE 8337/udp
EXPOSE 8338/tcp

# S6 entrypoint
ENTRYPOINT ["/init"]