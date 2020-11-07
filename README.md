# CISA: Cyber Hygiene Core Libraries

This project contains the core libraries and executables for the CISA Cyber Hygiene program.  It coordinates the multiple scanners and allows the creation of pretty reports.

## CyHy Configuration

The `cyhy-core` library requires a configuration be created.  The default location for this file is `/etc/cyhy/cyhy.conf`.  An example configuration is below.

### `/etc/cyhy/cyhy.conf`
```
[DEFAULT]
default-section = cyhy-ops-ssh-tunnel-docker-mac
report-key = master-report-password

[cyhy-ops-ssh-tunnel-docker-mac]
database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@host.docker.internal:27017/cyhy
database-name = cyhy

[cyhy-ops-ssh-tunnel-docker]
database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@localhost:27017/cyhy
database-name = cyhy

[cyhy-ops-staging-read]
database-uri = mongodb://<MONGO_USERNAME>:<MONGO_PASSWORD>@database1:27017/cyhy
database-name = cyhy
```

## Using CyHy Commands with Docker
The CyHy commands implemented in the docker container can be aliased into the host environment by using the procedure below.

Alias the container commands to the local environment:
```bash
eval "$(docker run cisagov/cyhy-core)"
```

To run a CyHy command:
```console
cyhy-tool status NASA
```

### Caveats, and Gotchas

Whenever an aliased CyHy command is executed, it will use the current working directory as its home volume.  This limits your ability to use absolute paths as parameters to commands, or relative paths that reference parent directories, e.g.; `../foo`.  That means all path parameters to a CyHy command must be in the current working directory, or a subdirectory.

| Do this?        | Command                                   | Reason  |
| ------------- |---------------------------------------------| --------|
| Yes           | `cyhy-import NASA.json`                     | parameter file is in the current directory |
| Yes           | `cyhy-import space_agencies/NASA.json`      | parameter file is in a sub-directory |
| NO!           | `cyhy-import ../WH.json`                    | parameter file is in a parent directory |
| NO!           | `cyhy-import /tmp/SPACE_FORCE.json`         | parameter file is an absolute path |

### Advanced configuration

By default, the container will look for your CyHy configurations in `/etc/cyhy`.  This location can be changed by setting the `CYHY_CONF_DIR` environment variable to point to your CyHy configuration directory.  The commands will also attempt to run using the `cisagov/cyhy-core` image.  A different image can be used by setting the `CYHY_CORE_IMAGE` environment variable to the image name.

Example:
```bash
export CYHY_CONF_DIR=/private/etc/cyhy
export CYHY_CORE_IMAGE=cisagov/cyhy-core
```

### Building the cyhy-core container
If you want to include a MaxMind GeoIP2 database in the docker image you must
provide a key and optionally the type of key to Docker. The default type is
"lite", but if you have the subscription license you can instead use the
"full" type.

The following commands show how to build the Docker container for cyhy-core.

#### No MaxMind license
```console
docker build --tag cisagov/cyhy-core .
```

#### MaxMind GeoLite2 license
```console
docker build --tag cisagov/cyhy-core \
             --build-arg maxmind_license_key=<license key> .
```

#### MaxMind GeoIP2 license
```console
docker build --tag cisagov/cyhy-core \
             --build-arg maxmind_license_type="full" \
             --build-arg maxmind_license_key=<license key> .
```

**WARNING: Be careful- you really don't want to push a Docker image to the
public Docker Hub if it was built with your MaxMind license key!**

### Building a cyhy-core image for distribution
The helper script `generate_cyhy_docker_image.sh` can be used to automate
building and saving a Docker image.

```console
Usage:
  generate_cyhy_docker_image.sh [options]

Options:
  -i, --image-name=NAME  Image name to use [default: cisagov/cyhy-core].
  -t, --image-tag=TAG    Image tag to use [default: latest].
  -h, --help             Display this message.

Notes:
- Requires Docker and the AWS CLI to run.
```

#### Default name and tag
```console
./generate_cyhy_docker_image.sh
```

#### Default name and specified tag
```console
./generate_cyhy_docker_image.sh testing
```

#### Specified name and tag
```console
./generate_cyhy_docker_image.sh cisagov/cyhy-core testing
```

## Manual Installation
Required third party libraries can be installed using: `pip install -r requirements.txt`

Required configurations:
The commander will read `/etc/cyhy/commander.conf`
If you do not have this file, please create one (even if empty)


IP Address Geolocation Database:
The geolocation database is not included in the source tree due to size and licensing.  Please cd into the `var` directory and run the `get-geo-db.sh` script to get the latest database.

## Development Installation
If you are developing the source the following installation will allow in place editing with live updates to the libraries, and command line utilities.

`sudo pip install numpy`

`sudo port install geos`

`sudo pip install -r requirements.txt`
