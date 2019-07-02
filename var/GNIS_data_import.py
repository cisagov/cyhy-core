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
  --force                        Force loading of the provided file.

"""

import csv
import re
import sys

from docopt import docopt

from cyhy.db import database

# Data file source: https://www.usgs.gov/core-science-systems/ngp/board-on-geographic-names/download-gnis-data
GOVT_UNITS_HEADER = "FEATURE_ID|UNIT_TYPE|COUNTY_NUMERIC|COUNTY_NAME|STATE_NUMERIC|STATE_ALPHA|STATE_NAME|COUNTRY_ALPHA|COUNTRY_NAME|FEATURE_NAME"
POP_PLACES_HEADER = "FEATURE_ID|FEATURE_NAME|FEATURE_CLASS|STATE_ALPHA|STATE_NUMERIC|COUNTY_NAME|COUNTY_NUMERIC|PRIMARY_LAT_DMS|PRIM_LONG_DMS|PRIM_LAT_DEC|PRIM_LONG_DEC|SOURCE_LAT_DMS|SOURCE_LONG_DMS|SOURCE_LAT_DEC|SOURCE_LONG_DEC|ELEV_IN_M|ELEV_IN_FT|MAP_NAME|DATE_CREATED|DATE_EDITED"


def exit_if_imported(fname):
    """Exit if the file appears to already have been loaded."""
    print "EXITING without importing any documents."
    print "The places collection already has {} loaded.".format(fname)
    sys.exit(0)


def is_imported(db, f, type):
    """Check if the provided file has already been loaded into the database.

    This check is done by seeing if the first and last records are already in
    the database.
    NOTE: This method is entirely reliant on Python 2 file reading behavior.
    """
    # GOVT_UNITS
    if type == 0:
        header = GOVT_UNITS_HEADER
    # POP_PLACES
    elif type == 1:
        header = POP_PLACES_HEADER
    else:
        return False

    name_idx = header.split("|").index("FEATURE_NAME")

    marker = f.tell()
    # Get the first record.
    while True:
        first_data_line = f.readline()
        if first_data_line.lstrip()[0] == "#":  # Skip commented out lines.
            pass
        else:
            break

    # Seek to the second to last byte in the file (to avoid any trailing newline).
    f.seek(-2, 2)
    # Get the last record
    while True:
        while f.read(1) != "\n" and marker < f.tell():
            f.seek(-2, 1)  # Seek to the byte before the one we just read.
        pos = f.tell()
        last_data_line = f.readline()
        if last_data_line.lstrip()[0] == "#":  # Skip commented out lines.
            # Reset location to one byte before the line just read.
            f.seek(pos)
            f.seek(-1, 1)
            pass
        else:
            break

    first_record = first_data_line.strip().split("|")
    last_record = last_data_line.strip().split("|")
    if (
        db.PlaceDoc.find_one(
            {"_id": long(first_record[0]), "name": first_record[name_idx]}
        )
        is not None
        and db.PlaceDoc.find_one(
            {"_id": long(last_record[0]), "name": last_record[name_idx]}
        )
        is not None
    ):
        return True

    f.seek(marker)
    return False


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

    with open(args["PLACES_FILE"], "r") as place_file:
        header_line = (
            place_file.readline().strip().decode("utf-8-sig")
        )  # Files downloaded from geonames.usgs.gov are UTF8-BOM
        csv_reader = csv.DictReader(
            skip_comments(place_file), delimiter="|", fieldnames=header_line.split("|")
        )

        if header_line == GOVT_UNITS_HEADER:
            if args["--force"] is not True:
                if is_imported(db, place_file, 0):
                    exit_if_imported(args["PLACES_FILE"])
            import_govt_units(db, csv_reader)
        elif header_line == POP_PLACES_HEADER:
            if args["--force"] is not True:
                if is_imported(db, place_file, 1):
                    exit_if_imported(args["PLACES_FILE"])
            import_populated_places(
                db, csv_reader
            )  # IMPORTANT: This import must be done AFTER import_govt_units()
        else:
            print "ERROR: Unknown header line found in: {}".format(args["PLACES_FILE"])
            sys.exit(-1)

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)


if __name__ == "__main__":
    main()
