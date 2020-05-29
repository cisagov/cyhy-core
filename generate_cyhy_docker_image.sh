#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

IMAGE_TAG="ncats/cyhy-core"
IMAGE_VERSION="latest"

IMAGE_OUTPUT_FILE="ncats_cyhy_core_docker_image_$(date +'%Y%m%d').tgz"

docker build --tag $IMAGE_TAG:$IMAGE_VERSION \
             --build-arg geoip_license_type="paid" \
             --build-arg geoip_license_key="$(< maxmind_license.txt)" .
docker save $IMAGE_TAG:$IMAGE_VERSION | gzip > "$IMAGE_OUTPUT_FILE"
