#!/usr/bin/env python

"""Change the _id and acronym of an organization across all CyHy database collections.

Usage:
  id_update.py [options] OLD_OWNER NEW_OWNER
  id_update.py (-h | --help)
  id_update.py --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.

"""

import sys
from docopt import docopt
from cyhy.db import database
from cyhy.util import util


def main():
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    old_owner = args["OLD_OWNER"]
    new_owner = args["NEW_OWNER"]

    if not util.warn_and_confirm("This will modify database documents."):
        print >> sys.stderr, "Aborted."
        sys.exit(-2)
    print >> sys.stderr

    # cannot replace _id...so must save and remove old doc
    # store the document in a variable
    for collection in (db.requests, db.tallies):
        doc = collection.find_one({"_id": old_owner})
        if doc == None:
            if collection == db.tallies:
                print >> sys.stderr, "WARNING: Organization does not have a tally document."
                break
            print >> sys.stderr, "ERROR: Organization does not have a request document."
            sys.exit(-1)
        if collection.find_one({"_id": new_owner}):
            print >> sys.stderr, "ERROR: An organization with _id {} exists.".format(
                new_owner
            )
            sys.exit(-1)
        # set a new _id on the document
        doc["_id"] = new_owner
        # insert the document, using the new _id
        collection.insert(doc)
        # remove the document with the old _id
        collection.remove({"_id": old_owner})
        print "  1 {} document modified".format(collection.name)

    db.requests.update(
        {"_id": new_owner},
        {"$set": {"agency.acronym": new_owner}},
        upsert=False,
        multi=False,
        safe=True,
    )

    for collection in (
        db.host_scans,
        db.hosts,
        db.port_scans,
        db.snapshots,
        db.tickets,
        db.vuln_scans,
        db.reports,
    ):
        result = collection.update(
            {"owner": old_owner},
            {"$set": {"owner": new_owner}},
            upsert=False,
            multi=True,
            safe=True,
        )
        result["collection"] = collection.name
        print "  {nModified} {collection} documents modified".format(**result)

    # Update all request docs that have OLD_OWNER in their list of children; remove OLD_OWNER then add NEW_OWNER
    for request_doc in db.RequestDoc.find({"children": old_owner}):
        request_doc["children"].remove(old_owner)
        request_doc["children"].append(new_owner)
        request_doc.save()
        print "  Updated list of children in {} request document".format(
            request_doc["_id"]
        )


if __name__ == "__main__":
    main()
