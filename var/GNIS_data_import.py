#!/usr/bin/env python

'''Import GNIS and FIPS data into the places collection.

Usage:
  COMMAND_NAME [--section SECTION] [--force] PLACES_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
  --force                        Force loading the provided file.

'''

import csv
import re
import sys

from docopt import docopt

from cyhy.db import database

# Data file source: https://geonames.usgs.gov/domestic/download_data.htm
GOVT_UNITS_HEADER = 'FEATURE_ID|UNIT_TYPE|COUNTY_NUMERIC|COUNTY_NAME|STATE_NUMERIC|STATE_ALPHA|STATE_NAME|COUNTRY_ALPHA|COUNTRY_NAME|FEATURE_NAME'
POP_PLACES_HEADER = 'FEATURE_ID|FEATURE_NAME|FEATURE_CLASS|STATE_ALPHA|STATE_NUMERIC|COUNTY_NAME|COUNTY_NUMERIC|PRIMARY_LAT_DMS|PRIM_LONG_DMS|PRIM_LAT_DEC|PRIM_LONG_DEC|SOURCE_LAT_DMS|SOURCE_LONG_DMS|SOURCE_LAT_DEC|SOURCE_LONG_DEC|ELEV_IN_M|ELEV_IN_FT|MAP_NAME|DATE_CREATED|DATE_EDITED'

def import_govt_units(db, csv_reader):
    for line in csv_reader:
        if line[0][0] != '#':       # skip commented-out lines
            placeDoc = db.PlaceDoc({'_id':long(line[0]), 'class':line[1], 'county_fips':line[2], 'county':line[3],
                                    'state_fips':line[4], 'state':line[5], 'state_name':line[6],
                                    'country':line[7], 'country_name':line[8], 'name':line[9]})
            placeDoc.save()

def import_populated_places(db, csv_reader):
    # IMPORTANT: This import must be done AFTER import_govt_units()
    all_states = db.PlaceDoc.find({'class':'STATE'})
    state_lookup = dict()
    for state in all_states:
        state_lookup[state['state']] = {'state_name':state['state_name'], 'country':state['country'], 'country_name':state['country_name']}

    for line in csv_reader:
        if line[0][0] != '#':       # skip commented-out lines
            placeDoc = db.PlaceDoc({'_id':long(line[0]), 'name':line[1], 'class':line[2], 'state':line[3], 'state_fips':line[4],
                                    'county':line[5], 'county_fips':line[6], 'latitude_dms':line[7], 'longitude_dms':line[8],
                                    'latitude_dec':float(line[9]), 'longitude_dec':float(line[10])})
            if line[15]:
                placeDoc['elevation_meters'] = int(line[15])
            else:
                placeDoc['elevation_meters'] = None
            if line[16]:
                placeDoc['elevation_feet'] = int(line[16])
            else:
                placeDoc['elevation_feet'] = None
            placeDoc['state_name'] = state_lookup[placeDoc['state']]['state_name']
            placeDoc['country'] = state_lookup[placeDoc['state']]['country']
            placeDoc['country_name'] = state_lookup[placeDoc['state']]['country_name']
            placeDoc.save()

def main():
    global __doc__
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])

    with open(args['PLACES_FILE'], 'r') as place_file:
        header_line = place_file.readline().strip().decode('utf-8-sig')     # Files downloaded from geonames.usgs.gov are UTF8-BOM

        # Check if the file has already been loaded by seeing if the first and last
        # records are already in the database.
        # NOTE: This method is entirely reliant on Python 2 file reading behavior.
        if args["--force"] is not True:
            marker = place_file.tell()
            # Get the first record.
            while True:
                first_line = place_file.readline()
                if first_line[0] == "#":    # Skip commented out lines.
                    pass
                else:
                    break

            # Get the last record
            place_file.seek(-2, 2)
            while True:
                while place_file.read(1) != '\n' and marker < place_file.tell():
                    place_file.seek(-2, 1)  # Seek to the byte before the one we just read.
                pos = place_file.tell()
                last_line = place_file.readline()
                if last_line[0] == "#": # Skip commented out lines.
                    # Reset location to one byte before the line just read.
                    place_file.seek(pos)
                    place_file.seek(-1,1)
                    pass
                else:
                    break

            if (db.places.find_one({"_id": long(first_line.split("|")[0])}) is not None
                and db.places.find_one({"_id": long(last_line.split("|")[0])}) is not None):
                print 'EXITING without importing any documents.'
                print 'The places collection already has {} loaded.'.format(args['PLACES_FILE'])
                sys.exit(0)

            place_file.seek(marker)

        csv_reader = csv.reader(place_file, delimiter='|')

        if header_line == GOVT_UNITS_HEADER:
            import_govt_units(db, csv_reader)
        elif header_line == POP_PLACES_HEADER:
            import_populated_places(db, csv_reader)     # IMPORTANT: This import must be done AFTER import_govt_units()
        else:
            print 'ERROR: Unknown header line found in: {}'.format(args['PLACES_FILE'])
            sys.exit(-1)

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)

if __name__=='__main__':
    main()
