#!/usr/bin/env bash
#
# Generate a cyhy-core Docker image for distribution to the CyHy Team.

set -o nounset
set -o errexit
set -o pipefail

IMAGE_NAME="cisagov/cyhy-core"
IMAGE_TAG="latest"

# Print usage information and exit with the provided exit code.
function usage {
  echo "Usage:"
  echo "  ${0##*/} [options]"
  echo
  echo "Options:"
  echo "  -i, --image-name=NAME  Image name to use [default: $IMAGE_NAME]."
  echo "  -t, --image-tag=TAG    Image tag to use [default: $IMAGE_TAG]."
  echo "  -h, --help             Display this message."
  exit "$1"
}

# Check for required external programs. If any are missing output a list of all
# requirements and then exit.
function check_dependencies {
  required_tools="aws docker"
  for tool in $required_tools
  do
    if [ -z "$(command -v "$tool")" ]
    then
      echo "This script requires the following tools to run:"
      for item in $required_tools
      do
        echo "- $item"
      done
      exit 1
    fi
  done
}

while (( "$#" ))
do
  case "$1" in
    -h|--help)
      usage 0
      ;;
    -n|--image-name)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]
      then
        IMAGE_NAME=$2
        shift 2
      else
        usage 1
      fi
      ;;
    -t|--image-tag)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]
      then
        IMAGE_TAG=$2
        shift 2
      else
        usage 1
      fi
      ;;
    -*)
      usage 1
      ;;
  esac
done

check_dependencies

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
