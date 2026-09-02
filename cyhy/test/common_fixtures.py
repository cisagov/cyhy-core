import os

import pytest

from cyhy.db import database as pcsdb
from cyhy.db import CHDatabase
from testenv import DB_NAME_VAR, DB_URI_VAR, DEFAULT_DB_NAME, DEFAULT_DB_URI


@pytest.fixture
def database(dockerc):
    # The dockerc fixture guarantees that MongoDB is up and accepting
    # connections before this fixture is used.
    #
    # Connect directly instead of by way of db_from_config() so that running the
    # tests does not require a CyHy configuration file to be installed at
    # /etc/cyhy/cyhy.conf, and so a test run cannot be pointed at a production
    # database by whatever configuration happens to be on the machine.
    return pcsdb.db_from_connection(
        os.environ.get(DB_URI_VAR, DEFAULT_DB_URI),
        os.environ.get(DB_NAME_VAR, DEFAULT_DB_NAME),
    )


@pytest.fixture
def ch_db(database):
    return CHDatabase(database)
