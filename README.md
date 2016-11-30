# Dagda
[![Build Status](https://travis-ci.org/eliasgranderubio/dagda.svg?branch=master)](https://travis-ci.org/eliasgranderubio/dagda)
[![Coverage Status](https://coveralls.io/repos/github/eliasgranderubio/dagda/badge.svg?branch=master)](https://coveralls.io/github/eliasgranderubio/dagda?branch=master)

**Dagda** is a tool to perform static analysis of known vulnerabilities in docker images/containers.

In order to fulfill its mission, first the known vulnerabilities as CVEs (Common Vulnerabilities and Exposures) and BIDs (Bugtraq IDs), and the known exploits from Offensive Security database are imported into a MongoDB to facilitate search of these vulnerabilities and exploits when your analysis are in progress.

Then, when you run an analysis, **Dagda** retrieves information about the software installed into your analyzed docker image and verifies for each product and its version if it is free of vulnerabilities against the previously stored information into the MongoDB.

Finally, each analysis result of a docker image is stored into the same MongoDB for having available the history of each docker image/container when it is needed.

   * [Requirements](#requirements)
  	 * [Installation of Docker](#installation-of-docker)
     * [Installation of MongoDB](#installation-of-mongodb)
   * [Populating the database](#populating-the-database)
     * [Database contents](#database-contents)
   * [Usage](#usage)
   * [Bonus Track: Quick Start with Docker](#bonus-track-quick-start-with-docker)
   * [Roadmap](#roadmap)
   * [Bugs and Feedback](#bugs-and-feedback)

## Requirements
Before **Dagda** usage, you must have installed Python >= 3.4.5 and the next requirements:

* Python3.4.5 or later
* MongoDB 2.4 or later
* Docker
* Pip3
  * PyMongo
  * Requests
  * Progressbar2
  * Docker-py

The requirements can be installed with pip:
```
    sudo pip3 install -r requirements.txt
```

### Installation of Docker

You must have installed Docker for using **Dagda**. If you need instructions for Docker installation, see the [How-to install Docker](https://docs.docker.com/engine/getstarted/step_one/) page.

In order to avoid having to use `sudo` when you use the `docker` command, create a Unix group called `docker` and add users to it. When the `docker` daemon starts, it makes the ownership of the Unix socket read/writable by the `docker` group.

### Installation of MongoDB

You must have installed MongoDB 2.4 or later for using **Dagda** because in MongoDB are stored both the vulnerabilities/exploits and the analysis results.

If you need instructions for MongoDB installation, see the [How-to install MongoDB Community Edition](https://docs.mongodb.com/manual/administration/install-community/) page.

You can also run MongoDB using docker:
```
    docker pull mongo
    docker run -d -p 27017:27017 mongo
```

## Populating the database

For the initial run, you need to populate the vulnerabilities and the exploits in the database by running:
```
    python3 vuln_db.py --init
```

If you need repopulating your database for update with the new vulnerabilities and exploits, you only need rerun the previous command.

Also, you can run queries on your personal database with this tool. Below, the help when you type `python3 vuln_db.py -h` is shown:
```
    usage: vuln_db.py [-h] [--init] [--bid BID] [--cve CVE]
                      [--exploit_db EXPLOIT_DB] [--product PRODUCT]
                      [--product_version PRODUCT_VERSION] [-v]

    Your personal CVE, BID & ExploitDB database.

    optional arguments:
      -h, --help            show this help message and exit
      --init                initializes your local database with all CVEs provided
                            by NIST publications, all BugTraqs Ids (BIDs)
                            downloaded from the "http://www.securityfocus.com/"
                            pages (See my project "bidDB_downloader"
                            [https://github.com/eliasgranderubio/bidDB_downloader]
                            for details) and all exploits from Offensive Security
                            Exploit Database. If this argument is present, all
                            CVEs, BIDs and exploits of your local database will be
                            removed and then, will be inserted again with all
                            updated CVEs, BIDs and exploits.
      --bid BID             all product with this BugTraq Id (BID) vulnerability
                            will be shown
      --cve CVE             all products with this CVE vulnerability will be shown
      --exploit_db EXPLOIT_DB
                            all products with this Exploit_DB Id vulnerability
                            will be shown
      --product PRODUCT     all CVE/BID vulnerabilities and exploits of this
                            product will be shown
      --product_version PRODUCT_VERSION
                            extra filter for product query about its CVE/BID
                            vulnerabilities and exploits. If this argument is
                            present, the "--product" argument must be present too
      -v, --version         show the version message and exit
```

Fulfilling with the described usage, a usage example would be the next one (Keep in mind that `--product_version` is a optional argument)
```
    python3 vuln_db.py --product openldap --product_version 2.2.20
```

The expected output is shown below:
```
    [
        "CVE-2005-4442",
        "CVE-2006-2754",
        "CVE-2006-5779",
        "CVE-2006-6493",
        "CVE-2007-5707",
        "CVE-2007-5708",
        "CVE-2011-4079",
        "BID-83610",
        "BID-83843"
    ]
```

### Database contents

The database is called `vuln_database` and there are 3 collections:

* cve (Common Vulnerabilities and Exposure items) - source NVD NIST
* bid (BugTraqs Ids items from `http://www.securityfocus.com/`) - source [bidDB_downloader](https://github.com/eliasgranderubio/bidDB_downloader)
* exploit_db (Offensive Security - Exploit Database) - source [Offensive Security](https://github.com/offensive-security/exploit-database)

## Usage
**IMPORTANT NOTE:** In this **Dagda** version, the `docker pull` command must be run out-of-the-box because this functionality is not included. That is way, the docker image must be in the host when you run `check_docker`.

Below, the help when you type `python3 check_docker.py --help` is shown:

```
    usage: check_docker.py [-h] [-i DOCKER_IMAGE] [-c CONTAINER_ID] [-v]

    Your personal docker security analyzer.

    optional arguments:
      -h, --help            show this help message and exit
      -i DOCKER_IMAGE, --docker_image DOCKER_IMAGE
                            the input docker image name
      -c CONTAINER_ID, --container_id CONTAINER_ID
                            the input docker container id
      -v, --version         show the version message and exit
```

Fulfilling with the described usage, a usage example would be the next one (note that the expected output has been shortened):
```
	python3 check_docker.py --docker_image jboss/wildfly
```

The expected output is shown below:
```
    {
        "total_products": 182,
        "ok_products": 141,
        "vuln_products": 41,
        "image_name": "jboss/wildfly",
        "timestamp": "2016-11-29 19:01:36.144439",
        "evaluated_packages_info": [{
            "product": "sed",
            "version": "4.2.2"
            "is_vulnerable": false,
            "vulnerabilities": []
        }, {
            "product": "grep",
            "version": "2.20",
            "is_vulnerable": true,
            "vulnerabilities": [
                "CVE-2015-1345"
            ]
        {
            "product": "lua",
            "version": "5.1.4",
            "is_vulnerable": true,
            "vulnerabilities": [
                "CVE-2014-5461",
                "BID-34237"
            ]
        },
        [...]
        , {
            "product": "sqlite",
            "version": "3.7.17",
            "is_vulnerable": false,
            "vulnerabilities": []
        }]
    }
```

If you want review the history of a concrete docker analysis, you must type `python3 docker_history.py <DOCKER_IMAGE_NAME_HERE>`. Below, the help when you type `python3 docker_history.py --help` is shown:

```
    usage: docker_history.py [-h] [-v] IMAGE_NAME

    Your personal docker security analyzer history.

    positional arguments:
      IMAGE_NAME     the analysis history for the requested docker image name will
                     be shown ordered by descending date

    optional arguments:
      -h, --help     show this help message and exit
      -v, --version  show the version message and exit
```

## Bonus Track: Quick Start with Docker

This section describes the installation of **Dagda** using Docker containers, including the Mongo database and a container for **Dagda**, using ```docker-compose```. The docker socket is shared with the **Dagda** container, so it is possible to check docker images and containers from the host where ```docker-compose``` is executed.

Execute the following commands in the root folder of **Dagda** (note that the `docker-compose run` commands can be replaced for any supported command described in this documentation):

```
    $ docker-compose build
    $ docker-compose run --rm dagda vuln_db.py --init
    $ docker-compose run --rm dagda check_docker.py -c <container_id>
```

## Roadmap

### 0.3.0 (Work in progress)

Dagda 0.3.0 is currently in the planning phase.

#### Wish list

If you want contribute to this project, feel free to do it. That's why the wish list for this version is shown below:
* Analyze more software than the installed software in the Operating System
    * Analyze Java dependencies such as the [OWASP dependency-check](https://github.com/jeremylong/DependencyCheck) project
    * Analyze Javascript dependencies such as the [Retire.js](https://github.com/RetireJS/retire.js) project

### 0.2.0 (Released)

The following features are already implemented and included in the 0.2.0 release.
* Minimized the false positives improving the accuracy of the matches between the information retrieved from the docker images and the stored information into the MongoDB
* Improved the user feedback for the long time running processes
* Improved the accuracy of the external vulnerabilities/exploits parser
* Created a quick starter with Docker
* **Dagda** project included in a CI environment
* Added tests for code coverage

### 0.1.0 (Released)

The following features are already implemented and included in the 0.1.0 release.
* Analyzes the installed software in the Operating System
* Analyzes both the docker images and the running containers
* Docker analysis history supported
* Multiple Linux base images supported
    * Red Hat/CentOS/Fedora
    * Debian/Ubuntu
    * OpenSUSE
    * Alpine
* Multiple vulnerabilities and exploits sources
    * CVEs
    * BugTraqs
    * Exploit-db
* CLI for querying your personal database which contains the vulnerabilities and the exploits from the imported sources

## Bugs and Feedback
For bugs, questions and discussions please use the [Github Issues](https://github.com/eliasgranderubio/dagda/issues) or ping me on Twitter (@3grander).
