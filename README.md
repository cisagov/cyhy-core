NCATS Scanner
=============

The NCATS scanner is the core of the Cyber Hygiene program.  It coordinates the multiple scanners and allows the creation of pretty reports.  

Installation
------------

Required third party libraries can be installed using: `pip install -r requirements.txt`

Required configurations:
The commander will read `/etc/cyhy/commander.conf`
If you do not have this file, please create one (even if empty)


IP Address Geolocation Database:
The geolocation database is not included in the source tree due to size and licensing.  Please cd into the 'var' directory and run the 'get-geo-db.sh' script to get the latest database.

Development Installation
------------------------
If you are developing the source the following installation will allow in place editing with live updates to the libraries, and command line utilities.

sudo pip install numpy
sudo port install geos
sudo pip install -r requirements.txt

Docker Goodies
--------------
Preliminary support for Docker has been added.  The commands can all be mapped into the host path using the procedure below.  Note that the container will use the current working directory as its home.  So all path parameters must be in the current working directory, or a subdirectory.  

Expose the container commands to the local environment:
```bash
eval "$(docker run ncats/cyhy-core)"
```

By default, the container will look for your CyHy configurations in `/etc/cyhy`.  This location can be changed by setting the `CYHY_CONF_DIR` environment variable to point to your CyHy configuration directory.  The commands will also attempt to run using the `ncats/cyhy-core` image.  A different image can be used by setting the `CYHY_CORE_IMAGE` environment variable to the image name.

Example:
```
export CYHY_CONF_DIR=~/.cyhy
export CYHY_CORE_IMAGE=dhub.ncats.dhs.gov:5001/cyhy-core
```


To build the Docker container for cyhy-core:

```bash
docker build -t ncats/cyhy-core .
```


To run a command:
```bash
cyhy-tool -s production-reporter status NASA
```

To attach a shell:
```bash
docker exec -ti cyhy-core /bin/bash
```
