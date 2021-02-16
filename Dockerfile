# NOTE: Be careful- you really don't want to push this Docker image to the
# public Docker Hub if it was built with your MaxMind license key!

FROM debian:stretch-slim
LABEL maintainer="Mark Feldhousen <mark.feldhousen@cisa.dhs.gov>"
LABEL description="Docker image to provide tools for interacting with the CyHy \
production database."
ENV CYHY_HOME="/home/cyhy" \
    CYHY_ETC="/etc/cyhy" \
    CYHY_CORE_SRC="/usr/src/cyhy-core" \
    PYTHONIOENCODING="utf8"
ARG maxmind_license_type="lite"
ARG maxmind_license_key

RUN groupadd --system cyhy && useradd --system --gid cyhy cyhy

RUN mkdir ${CYHY_HOME}
RUN chown cyhy:cyhy ${CYHY_HOME}
VOLUME ${CYHY_ETC} ${CYHY_HOME}

# Install required packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      curl \
      dirmngr \
      gnupg \
      python-dev \
      python-pip \
      python-setuptools \
      python-wheel

# Install system Python packages for cyhy-core requirements
# Sourced from:
# https://github.com/cisagov/ansible-role-cyhy-core/blob/develop/tasks/main.yml
RUN apt-get install -y --no-install-recommends \
    python-crypto \
    python-dateutil \
    python-docopt \
    python-geoip2 \
    python-maxminddb \
    python-netaddr \
    python-pandas \
    python-progressbar \
    python-six \
    python-yaml

# Install MongoDB shell from official repository
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4
RUN echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/4.0 main" | tee /etc/apt/sources.list.d/mongodb-org-4.0.list
RUN echo "deb http://deb.debian.org/debian stretch-backports main" | tee /etc/apt/sources.list.d/stretch-backports.list
RUN apt-get update && apt-get install -y mongodb-org-shell

# Clean up the apt cache
RUN apt-get clean

WORKDIR ${CYHY_CORE_SRC}

COPY . ${CYHY_CORE_SRC}
RUN pip install --no-cache-dir .[dev]
RUN pip install --no-cache-dir --requirement requirements-cyhy_ops.txt
RUN var/geoipupdate.sh $maxmind_license_type $maxmind_license_key
RUN ln -snf ${CYHY_CORE_SRC}/var/getenv /usr/local/bin
RUN ln -snf ${CYHY_CORE_SRC}/var/getopsenv /usr/local/bin

USER cyhy
WORKDIR ${CYHY_HOME}
CMD ["getenv"]
