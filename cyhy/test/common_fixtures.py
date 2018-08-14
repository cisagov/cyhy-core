import pytest
from cyhy.db import database as pcsdb
from cyhy.db import CHDatabase


@pytest.fixture
def database():
    #connection = MongoClient('mongodb://tester:tester@[::1]:27017/test_database2', 27017)
    #db = connection['test_database2']
    db = pcsdb.db_from_config('testing')
    return db

@pytest.fixture
def ch_db(database):
    return CHDatabase(database)
