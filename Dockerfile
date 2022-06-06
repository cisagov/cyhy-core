# NOTE: Be careful- you really don't want to push this Docker image to the
# public Docker Hub if it was built with your MaxMind license key!

FROM debian:buster-slim

# For a list of pre-defined annotation keys and value types see:
# https://github.com/opencontainers/image-spec/blob/master/annotations.md
# Note: Additional labels are added by the build workflow.
LABEL org.opencontainers.image.authors="mark.feldhousen@cisa.dhs.gov"
LABEL org.opencontainers.image.vendor="Cybersecurity and Infrastructure Security Agency"
LABEL org.opencontainers.image.description="Docker image to provide tools for interacting with the CyHy production database."

ARG maxmind_license_type="lite"
ARG maxmind_license_key

ENV CYHY_HOME="/home/cyhy" \
    CYHY_ETC="/etc/cyhy" \
    CYHY_CORE_SRC="/usr/src/cyhy-core" \
    PYTHONIOENCODING="utf8"

# Since we use pipes in some RUN commands we should ensure that if they fail it
# is correctly seen as an error.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN groupadd --system cyhy && useradd --system --gid cyhy cyhy
RUN mkdir ${CYHY_HOME} && chown cyhy:cyhy ${CYHY_HOME}
VOLUME ${CYHY_ETC} ${CYHY_HOME}

# Add MongoDB official repository and backports
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4 \
  && echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | tee /etc/apt/sources.list.d/mongodb-org-4.2.list \
  && echo "deb http://deb.debian.org/debian buster-backports main" | tee /etc/apt/sources.list.d/buster-backports.list

# Install required packages
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    dirmngr \
    gnupg \
    mongodb-org-shell \
    python-crypto \
    python-dateutil \
    python-dev \
    python-docopt \
    python-geoip2 \
    python-maxminddb \
    python-netaddr \
    python-pandas \
    python-pip \
    python-progressbar \
    python-setuptools \
    python-six \
    python-wheel \
    python-yaml \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR ${CYHY_CORE_SRC}

COPY . ${CYHY_CORE_SRC}
RUN pip install --no-cache-dir .[dev] \
  && pip install --no-cache-dir --requirement requirements-cyhy_ops.txt
RUN var/geoipupdate.sh $maxmind_license_type $maxmind_license_key
RUN ln -snf ${CYHY_CORE_SRC}/var/getenv /usr/local/bin \
  && ln -snf ${CYHY_CORE_SRC}/var/getopsenv /usr/local/bin

USER cyhy
WORKDIR ${CYHY_HOME}
CMD ["getenv"]
