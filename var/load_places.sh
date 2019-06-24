#!/usr/bin/env bash

# load content for the places collection
# pass DB section as a command line argument

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DB_SECTION=$1
DATA_ROOT_URI="https://www.usgs.gov"
DATA_FILE_WEBPAGE_URL="${DATA_ROOT_URI}/core-science-systems/ngp/board-on-geographic-names/download-gnis-data"
PLACES_HTML="places_data.html"
TMP_PLACES_DIR="/tmp/places"
ADDL_PLACES_FILE="../extras/ADDL_CYHY_PLACES.txt"

# Create directory to temporarily store files while working.
mkdir -p ${TMP_PLACES_DIR}
cd ${TMP_PLACES_DIR}

curl -o "${PLACES_HTML}" "${DATA_FILE_WEBPAGE_URL}"

# download, unzip and import place files
# IMPORTANT: GOVT_UNITS must be imported to DB before POP_PLACES and ADDL_CYHY_PLACES
PLACE_FILES="GOVT_UNITS POP_PLACES"
for PLACE_TYPE in ${PLACE_FILES}
do
	PLACE_URI=$(grep "${PLACE_TYPE}" "${PLACES_HTML}" | cut -d'"' -f2)
	curl -O "${PLACE_URI}"
	unzip ./*"${PLACE_TYPE}"*.zip -d "${TMP_PLACES_DIR}"

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
	"${SCRIPT_DIR}/GNIS_data_import.py" -s "${DB_SECTION}" "${SCRIPT_DIR}/${ADDL_PLACES_FILE}"
fi

# clean up
#rm -R ${TMP_PLACES_DIR}
