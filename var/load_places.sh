#!/usr/bin/env bash

# load content for the places collection
# pass DB section as a command line argument

set -o nounset
set -o errexit
set -o pipefail

function usage() {
	echo "Usage:  ${0##*/} database_section"
	exit 0
}

if [ $# -gt 1 ]
then
	usage
else
	# Skeleton to allow additional options at a later date if so desired.
  while getopts ":h-:" opt; do
		case "${opt}" in
			"h")
				usage
				;;
			"-")
				usage
				;;
			*)
				usage
				;;
		esac
	done
fi

DB_SECTION="${1-}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Base URL for the zip files is derived from the listings at
# https://www.usgs.gov/core-science-systems/ngp/board-on-geographic-names/download-gnis-data
# for GOVT_UNITS and POP_PLACES
DATA_BASE_URL="https://geonames.usgs.gov/docs/stategaz/"

TMP_PLACES_DIR="/tmp/places"
ADDL_PLACES_FILE="../extras/ADDL_CYHY_PLACES.txt"

# Create and change to temporary working directory.
mkdir -p ${TMP_PLACES_DIR}
cd ${TMP_PLACES_DIR}

# download, unzip and import place files
# IMPORTANT: GOVT_UNITS must be imported to DB before POP_PLACES and ADDL_CYHY_PLACES
PLACE_FILES="GOVT_UNITS POP_PLACES"
for PLACE_TYPE in ${PLACE_FILES}
do
	PLACE_URI="${DATA_BASE_URL}${PLACE_TYPE}.zip"
	curl -O "${PLACE_URI}"
	unzip "./${PLACE_TYPE}.zip" -d "${TMP_PLACES_DIR}"

	PLACE_FILE=$(ls ${TMP_PLACES_DIR}/*"${PLACE_TYPE}"*.txt)
	echo "Importing ${PLACE_FILE} to DB..."
	if [ -z "${DB_SECTION}" ]; then
		"${SCRIPT_DIR}/GNIS_data_import.py" "${PLACE_FILE}"
	else
		"${SCRIPT_DIR}/GNIS_data_import.py" -s "${DB_SECTION}" "${PLACE_FILE}"
	fi
done

# import ADDL_CYHY_PLACES file into the DB
echo "Importing ${ADDL_PLACES_FILE} to DB..."
if [ -z "${DB_SECTION}" ]; then
	"${SCRIPT_DIR}/GNIS_data_import.py" "${SCRIPT_DIR}/${ADDL_PLACES_FILE}"
else
	"${SCRIPT_DIR}/GNIS_data_import.py" -s "${DB_SECTION}" \
		"${SCRIPT_DIR}/${ADDL_PLACES_FILE}"
fi

# clean up
rm -R ${TMP_PLACES_DIR}
