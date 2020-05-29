#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail

function usage {
  echo "Usage:"
  echo "  ${0##*/} (lite|full) <license key>"
  echo ""
  echo "Arguments:"
  echo "  lite  The license key is for the GeoLite2 database."
  echo "  full  The license key is for the GeoIP2 database."
  echo ""
  echo "Options:"
  echo "  license_key  The license key to use."
  exit 0
}

if [ $# -ne 2 ]
then
  usage
fi

license_type=$(echo "$1" | tr '[:upper:]' '[:lower:]')
license_key=$2

if [ "$license_type" == "lite" ]
then
  edition="GeoLite2-City"
elif [ "$license_type" == "full" ]
then
  edition="GeoIP2-City"
else
  usage
fi

GEOIP_CITY_URI="https://download.maxmind.com/app/geoip_download?edition_id=$edition&license_key=$license_key&suffix=tar.gz"
GEOIP_CITY_DIR="/usr/local/share/GeoIP/"

mkdir -p "$GEOIP_CITY_DIR"

curl "$GEOIP_CITY_URI" | tar zxf - --strip-components=1 --directory="$GEOIP_CITY_DIR"
