#!/usr/bin/env python

"""Import GNIS and FIPS data into the places collection.

Usage:
  COMMAND_NAME [--section SECTION] [--force] PLACES_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
"""
from __future__ import print_function

import csv
import io
import re
import sys

from docopt import docopt
from unidecode import unidecode

from cyhy.db import database

# Data file source: https://www.usgs.gov/core-science-systems/ngp/board-on-geographic-names/download-gnis-data
GOVT_UNITS_HEADER = "FEATURE_ID|UNIT_TYPE|COUNTY_NUMERIC|COUNTY_NAME|STATE_NUMERIC|STATE_ALPHA|STATE_NAME|COUNTRY_ALPHA|COUNTRY_NAME|FEATURE_NAME"
POP_PLACES_HEADER = "FEATURE_ID|FEATURE_NAME|FEATURE_CLASS|STATE_ALPHA|STATE_NUMERIC|COUNTY_NAME|COUNTY_NUMERIC|PRIMARY_LAT_DMS|PRIM_LONG_DMS|PRIM_LAT_DEC|PRIM_LONG_DEC|SOURCE_LAT_DMS|SOURCE_LONG_DMS|SOURCE_LAT_DEC|SOURCE_LONG_DEC|ELEV_IN_M|ELEV_IN_FT|MAP_NAME|DATE_CREATED|DATE_EDITED"


def unidecode_lines(lines):
    """Flatten Unicode characters to ASCII equivalents."""
    for line in lines:
        yield unidecode(line)


def skip_comments(lines):
    """Skip lines that contain a comment."""

    for line in lines:
        if line.lstrip()[0] != "#":
            yield line


def import_govt_units(db, csv_reader):
    for line in csv_reader:
        placeDoc = db.PlaceDoc(
            {
                "_id": long(line["FEATURE_ID"]),
                "class": line["UNIT_TYPE"],
                "county_fips": line["COUNTY_NUMERIC"],
                "county": line["COUNTY_NAME"],
                "state_fips": line["STATE_NUMERIC"],
                "state": line["STATE_ALPHA"],
                "state_name": line["STATE_NAME"],
                "country": line["COUNTRY_ALPHA"],
                "country_name": line["COUNTRY_NAME"],
                "name": line["FEATURE_NAME"],
            }
        )
        placeDoc.save()


def import_populated_places(db, csv_reader):
    # IMPORTANT: This import must be done AFTER import_govt_units()
    all_states = db.PlaceDoc.find({"class": "STATE"})
    state_lookup = dict()
    for state in all_states:
        state_lookup[state["state"]] = {
            "state_name": state["state_name"],
            "country": state["country"],
            "country_name": state["country_name"],
        }

    for line in csv_reader:
        placeDoc = db.PlaceDoc(
            {
                "_id": long(line["FEATURE_ID"]),
                "name": line["FEATURE_NAME"],
                "class": line["FEATURE_CLASS"],
                "state": line["STATE_ALPHA"],
                "state_fips": line["STATE_NUMERIC"],
                "county": line["COUNTY_NAME"],
                "county_fips": line["COUNTY_NUMERIC"],
                "latitude_dms": line["PRIMARY_LAT_DMS"],
                "longitude_dms": line["PRIM_LONG_DMS"],
                "latitude_dec": float(line["PRIM_LAT_DEC"]),
                "longitude_dec": float(line["PRIM_LONG_DEC"]),
            }
        )
        if line["ELEV_IN_M"]:
            placeDoc["elevation_meters"] = int(line["ELEV_IN_M"])
        else:
            placeDoc["elevation_meters"] = None

        if line["ELEV_IN_FT"]:
            placeDoc["elevation_feet"] = int(line["ELEV_IN_FT"])
        else:
            placeDoc["elevation_feet"] = None

        placeDoc["state_name"] = state_lookup[placeDoc["state"]]["state_name"]
        placeDoc["country"] = state_lookup[placeDoc["state"]]["country"]
        placeDoc["country_name"] = state_lookup[placeDoc["state"]]["country_name"]
        placeDoc.save()


def main():
    global __doc__
    __doc__ = re.sub("COMMAND_NAME", __file__, __doc__)
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])

    # Files downloaded from geonames.usgs.gov are UTF8-BOM
    with io.open(args["PLACES_FILE"], encoding="utf-8-sig") as place_file:
        csv_reader = csv.DictReader(
            skip_comments(unidecode_lines(place_file)), delimiter="|"
        )
        header_line = "|".join(csv_reader.fieldnames)

        if header_line == GOVT_UNITS_HEADER:
            import_govt_units(db, csv_reader)
        elif header_line == POP_PLACES_HEADER:
            import_populated_places(
                db, csv_reader
            )  # IMPORTANT: This import must be done AFTER import_govt_units()
        else:
            print("ERROR: Unknown header line found in: {}".format(args["PLACES_FILE"]))
            sys.exit(-1)

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)


if __name__ == "__main__":
    main()
