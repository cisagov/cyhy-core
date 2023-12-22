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
  echo "  -k, --maxmind-key KEY  The MaxMind GeoIP2 key to use (defaults to"
  echo "                         retrieval from AWS SSM)"
  echo "  -n, --image-name NAME  Image name to use [default: $IMAGE_NAME]."
  echo "  -t, --image-tag TAG    Image tag to use [default: $IMAGE_TAG]."
  echo "  -h, --help             Display this message."
  echo
  echo "Notes:"
  echo "- Requires Docker and optionally the AWS CLI to run."
  exit "$1"
}

# Check for required external programs. If any are missing output a list of all
# requirements and then exit.
function check_dependencies {
  required_tools="docker"
  for tool in $required_tools; do
    if [ -z "$(command -v "$tool")" ]; then
      echo "This script requires the following tools to run:"
      for item in $required_tools; do
        echo "- $item"
      done
      exit 1
    fi
  done
}

while (("$#")); do
  case "$1" in
    -h | --help)
      usage 0
      ;;
    -k | --maxmind-key)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        MAXMIND_LICENSE_KEY=$2
        shift 2
      else
        usage 1
      fi
      ;;
    -n | --image-name)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        IMAGE_NAME=$2
        shift 2
      else
        usage 1
      fi
      ;;
    -t | --image-tag)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
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

BASE_IMAGE_NAME="$(echo "$IMAGE_NAME" | tr "/" "_")_$IMAGE_TAG"
IMAGE_OUTPUT_FILE="${BASE_IMAGE_NAME}_$(date +'%Y%m%d').tgz"
if [ -z "${MAXMIND_LICENSE_KEY}" ]; then
  MAXMIND_LICENSE_KEY=$(aws ssm get-parameter \
    --output text \
    --name "/cyhy/core/geoip/license_key" \
    --with-decryption \
    | awk -F"\t" '{print $6}')
fi

docker build --tag "$IMAGE_NAME:$IMAGE_TAG" \
  --build-arg maxmind_license_type="full" \
  --build-arg maxmind_license_key="$MAXMIND_LICENSE_KEY" .
docker save "$IMAGE_NAME:$IMAGE_TAG" | gzip > "$IMAGE_OUTPUT_FILE"
