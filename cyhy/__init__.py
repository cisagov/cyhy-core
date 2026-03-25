# Standard Python Libraries
from pkgutil import extend_path
import sys as _sys

# https://www.python.org/dev/peps/pep-0420/
__path__ = extend_path(__path__, __name__)


#: Version info (major, minor, maintenance, status)
VERSION = (0, 0, 2)
STATUS = ""
__version__ = "%d.%d.%d" % VERSION[0:3] + STATUS

if _sys.version_info[0:2] < (2, 7):
    raise RuntimeError("Python 2.7.x or higher is required!")
