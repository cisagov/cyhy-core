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
Preliminary support for Docker has been added.  The commands can all be mapped into the host path using the alias.sh script below.  Note that the container's cyhy user can only write to the mapped home volume, which is the default working directory for all execs.

To build the Docker container for cyhy-core:

```bash
docker build -t ncats/cyhy-core .
```

To run the container:
```bash
docker run --rm --name cyhy-core --detach --volume /private/etc/cyhy:/etc/cyhy --volume /tmp/cyhy:/home/cyhy dhub.ncats.dhs.gov:5001/cyhy-core
```

Create aliases to the containers commands:
```bash
eval "$(docker exec cyhy-core getenv)"
```

To run a command:
```bash
cyhy-tool -s production-reporter status NASA
```

To attach a shell:
```bash
docker exec -ti cyhy-core /bin/bash
```
