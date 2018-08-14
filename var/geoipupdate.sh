#!/bin/sh

# this script was copied and modifed from the dev-libs/geoip-1.6.9 ebuild

set -o verbose

GEOIP_CITY_URI="http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz"
GEOIP_CITY_DIR="/usr/local/share/GeoIP/"
GEOIP_CITY_FILE="GeoLite2-City.mmdb"

mkdir -p ${GEOIP_CITY_DIR}

curl ${GEOIP_CITY_URI} | gunzip > ${GEOIP_CITY_DIR}/${GEOIP_CITY_FILE}
