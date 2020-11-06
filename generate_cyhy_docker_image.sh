#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

IMAGE_NAME="cisagov/cyhy-core"
IMAGE_TAG="latest"

if [ $# -eq 1 ]
then
  IMAGE_TAG=$1
elif [ $# -eq 2 ]
then
  IMAGE_NAME=$1
  IMAGE_TAG=$2
fi

IMAGE_OUTPUT_FILE="cisa_cyhy_core_docker_image_$(date +'%Y%m%d').tgz"
MAXMIND_LICENSE_KEY=$(aws ssm get-parameter \
                    --output text \
                    --name "/cyhy/core/geoip/license_key" \
                    --with-decryption \
                    | awk -F"\t" '{print $6}')


docker build --tag "$IMAGE_NAME:$IMAGE_TAG" \
             --build-arg maxmind_license_type="full" \
             --build-arg maxmind_license_key="$MAXMIND_LICENSE_KEY" .
docker save "$IMAGE_NAME:$IMAGE_TAG" | gzip > "$IMAGE_OUTPUT_FILE"
