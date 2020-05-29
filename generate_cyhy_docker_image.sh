#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

IMAGE_TAG="ncats/cyhy-core"
IMAGE_VERSION="latest"

if [ $# -eq 1 ]
then
  IMAGE_VERSION=$1
elif [ $# -eq 2 ]
then
  IMAGE_TAG=$1
  IMAGE_VERSION=$2
fi

IMAGE_OUTPUT_FILE="ncats_cyhy_core_docker_image_$(date +'%Y%m%d').tgz"

docker build --tag "$IMAGE_TAG:$IMAGE_VERSION" \
             --build-arg maxmind_license_type="full" \
             --build-arg maxmind_license_key="$(< maxmind_license.txt)" .
docker save "$IMAGE_TAG:$IMAGE_VERSION" | gzip > "$IMAGE_OUTPUT_FILE"
