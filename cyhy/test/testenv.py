"""Environment variables and defaults used to configure the test suite."""

# Connection information for the MongoDB instance used by the tests.  These
# defaults match the instance created by the Docker composition at the root of
# this repository, which the test suite starts automatically.
DEFAULT_DB_URI = "mongodb://localhost:27037/test-cyhy"
DEFAULT_DB_NAME = "test-cyhy"

# Set these to run the tests against a MongoDB instance other than the one
# provided by the Docker composition.
DB_NAME_VAR = "CYHY_TEST_DB_NAME"
DB_URI_VAR = "CYHY_TEST_DB_URI"

# Set this to any value to stop the test suite from starting and stopping the
# Docker composition itself.  This is useful when a suitable MongoDB instance is
# already available, for example one provided as a CI service container, or when
# keeping an instance running between test runs while debugging.
SKIP_COMPOSE_VAR = "CYHY_TEST_SKIP_COMPOSE"
