#!/bin/sh

# this script was copied and modifed from the dev-libs/geoip-1.6.9 ebuild

set -o verbose

if [ -z $1 ]
then
  GEOIP_CITY_URI="https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
else
  GEOIP_CITY_URI="https://download.maxmind.com/app/geoip_download?edition_id=GeoIP2-City&suffix=tar.gz&license_key=$1"
fi
GEOIP_CITY_DIR="/usr/local/share/GeoIP/"

mkdir -p ${GEOIP_CITY_DIR}

curl ${GEOIP_CITY_URI} | tar zxf - --strip-components=1 --directory=${GEOIP_CITY_DIR}
