#!/bin/bash

# start-cyhy-ops.sh
# Starts up an environment suitable for performing Cyber Hygiene operational tasks
# Usage:
#    source start-cyhy-ops.sh

# CYHY_HOME_DIR will be mapped to /home/cyhy within the CyHy Docker container
# environment. Any files used by or fed into the container must reside in this
# directory or a sub-directory of it.
CYHY_HOME_DIR="/tmp/cyhy"

# CYHY_ETC_DIR is where a valid cyhy.conf file must reside
# (details in Prerequisites section below)
CYHY_ETC_DIR="/private/etc/cyhy"

# CYHY_CORE_IMAGE is the Docker image containing the CyHy tools. Do not change
# this unless you are sure you know what you are doing.
CYHY_CORE_IMAGE="dhub.ncats.dhs.gov:5001/cyhy-core"

# Prerequisites:
#  - NCATS/CAL VPN access
#  - Docker (https://www.docker.com/get-docker) installed
#  - Trust NCATS internal Docker hub (dhub.ncats.dhs.gov:5001) certificate
#    * Mac: Open Safari and trust the certificate
#    * Linux: TBD
#  - Valid credentials in /etc/cyhy/cyhy.conf - SAMPLE:
# [DEFAULT]
# default-section = cyhy-ops-production-read
# report-key = foobar
#
# [cyhy-ops-production-read]
# database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@c3b1.data.ncats.dhs.gov:27017/cyhy
# database-name = cyhy
#
# [cyhy-ops-production-write]
# database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@c2b2.data.ncats.dhs.gov:27017/cyhy
# database-name = cyhy
#
# [cyhy-ops-staging-read]
# database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@c4b2.data.ncats.dhs.gov:27017/cyhy
# database-name = cyhy
#
# [cyhy-ops-staging-write]
# database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@c4b2.data.ncats.dhs.gov:27017/cyhy
# database-name = cyhy

# Create the CYHY_HOME_DIR and cd to it
mkdir -p $CYHY_HOME_DIR
cd $CYHY_HOME_DIR

# Start up the Docker container and name it cyhy-ops
docker run --rm --name cyhy-ops --detach --volume $CYHY_ETC_DIR:/etc/cyhy --volume $CYHY_HOME_DIR:/home/cyhy $CYHY_CORE_IMAGE

# Create aliases for all of the cyhy-ops commands
eval "$(docker exec cyhy-ops getopsenv)"

alias cyhy-bash="docker exec -it cyhy-ops /bin/bash"
