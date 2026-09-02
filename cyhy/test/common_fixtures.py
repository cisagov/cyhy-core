import os

import pytest

from cyhy.db import database as pcsdb
from cyhy.db import CHDatabase

# Connection information for the MongoDB instance used by the tests.  These
# defaults match the instance created by the Docker composition at the root of
# this repository (see docker-compose.yml), so the tests require no
# configuration to run against it.
DEFAULT_DB_URI = "mongodb://localhost:27037/test-cyhy"
DEFAULT_DB_NAME = "test-cyhy"

# Environment variables used to run the tests against a different MongoDB
# instance.
DB_URI_VAR = "CYHY_TEST_DB_URI"
DB_NAME_VAR = "CYHY_TEST_DB_NAME"


@pytest.fixture
def database():
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
