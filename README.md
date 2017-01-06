# Dagda
[![Build Status](https://travis-ci.org/eliasgranderubio/dagda.svg?branch=master)](https://travis-ci.org/eliasgranderubio/dagda)
[![Coverage Status](https://coveralls.io/repos/github/eliasgranderubio/dagda/badge.svg?branch=master)](https://coveralls.io/github/eliasgranderubio/dagda?branch=master)

**Dagda** is a tool to perform static analysis of known vulnerabilities in docker images/containers and to monitor runtime docker containers for detecting anomalous activities.

In order to fulfill its mission, first the known vulnerabilities as CVEs (Common Vulnerabilities and Exposures) and BIDs (Bugtraq IDs), and the known exploits from Offensive Security database are imported into a MongoDB to facilitate the search of these vulnerabilities and exploits when your analysis are in progress.

Then, when you run a static analysis of known vulnerabilities, **Dagda** retrieves information about the software installed into your docker image, such as the OS packages and the dependencies of the programming languages, and verifies for each product and its version if it is free of vulnerabilities against the previously stored information into the MongoDB.

**Dagda** supports multiple Linux base images:
  * Red Hat/CentOS/Fedora
  * Debian/Ubuntu
  * OpenSUSE
  * Alpine

Also, **Dagda** rests on [OWASP dependency check](https://github.com/jeremylong/DependencyCheck) + [Retire.js](https://github.com/retirejs/retire.js/) for analyzing multiple dependencies from:
  * java
  * python
  * nodejs
  * js
  * ruby
  * php

On the other hand, **Dagda** is integrated with [Sysdig Falco](http://www.sysdig.org/falco/) for monitoring runtime docker containers to detect anomalous activities.

Finally, each analysis report of a docker image/container, included all static analysis and all runtime monitoring, is stored into the same MongoDB for having available the history of each docker image/container when it is needed.

   * [Requirements](#requirements)
  	 * [Installation of Docker](#installation-of-docker)
     * [Installation of MongoDB](#installation-of-mongodb)
     * [Installation of kernel headers in the host OS](#installation-of-kernel-headers-in-the-host-os)
   * [Usage](#usage)
     * [Populating the database](#populating-the-database)
       * [Database contents](#database-contents)
     * [Analyzing docker images/containers](#analyzing-docker-imagescontainers)
       * [Performing static analysis of known vulnerabilities](#performing-static-analysis-of-known-vulnerabilities)
       * [Monitoring running containers for detecting anomalous activities](#monitoring-running-containers-for-detecting-anomalous-activities)
     * [Bonus Track: Quick Start with Docker](#bonus-track-quick-start-with-docker)
   * [Troubleshooting](#troubleshooting)
   * [Change Log](#change-log)
   * [Bugs and Feedback](#bugs-and-feedback)

## Requirements
Before **Dagda** usage, you must have installed Python >= 3.4.5 and the next requirements:

* Python3.4.5 or later
* MongoDB 2.4 or later
* Docker
* Pip3
  * PyMongo
  * Requests
  * Python-dateutil
  * Joblib
  * Docker-py
  * Flask

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

### Installation of kernel headers in the host OS

You must have installed the kernel headers in the host OS because **Dagda** is integrated with [Sysdig Falco](http://www.sysdig.org/falco/) for monitoring runtime docker containers to detect anomalous activities.

This can usually be done on Debian-like distributions with: `apt-get -y install linux-headers-$(uname -r)`

Or, on RHEL-like distributions: `yum -y install kernel-devel-$(uname -r)`

After that, run the command `/usr/lib/dkms/dkms_autoinstaller start` is recommended for avoiding the next Sysdig Falco error trace:
```
rmmod: ERROR: Module sysdig_probe is not currently loaded
```

## Usage

You must run `python3 dagda.py start` for starting the **Dagda** server. See the [*start* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#start-sub-command) in the wiki page for details.

After the **Dagda** server started and before the **Dagda** CLI usage, you must set the next environment variables as you need:
```
    export DAGDA_HOST='127.0.0.1'
    export DAGDA_PORT=5000
```

Although in this usage documentation only the CLI usage is shown, **Dagda** has a REST API for using it. See [REST API](https://github.com/eliasgranderubio/dagda/wiki/REST-API) documentation page for details.

### Populating the database

For the initial run, you need to populate the vulnerabilities and the exploits in the database by running:
```
    python3 dagda.py vuln --init
```
The previous command can take several minutes for finishing so be patient.

If you need repopulating your database for updating with the new vulnerabilities and exploits, you only need rerun the previous command.

Also, you can run queries on your personal database with `dagda.py vuln`. A usage example would be the next one:
```
    python3 dagda.py vuln --product openldap --product_version 2.2.20
```

The expected output for the previous query is shown below:
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

If you want to know more details about `dagda.py vuln`, type `python3 dagda.py vuln --help` or see the [*vuln* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#vuln-sub-command) in the wiki page.

#### Database contents

The database is called `vuln_database` and there are 3 collections:

* cve (Common Vulnerabilities and Exposure items) - source NVD NIST
* bid (BugTraqs Ids items from `http://www.securityfocus.com/`) - source [bidDB_downloader](https://github.com/eliasgranderubio/bidDB_downloader)
* exploit_db (Offensive Security - Exploit Database) - source [Offensive Security](https://github.com/offensive-security/exploit-database)

### Analyzing docker images/containers

In the next subsections, both, performing static analysis of known vulnerabilities and monitoring running docker containers for detecting anomalous activities will be described in depth.

#### Performing static analysis of known vulnerabilities
One of the main **Dagda** targets is perform the analysis of known vulnerabilities in docker images/containers, so if you want perform an analysis over a docker image/container, you must type:
```
	python3 dagda.py check --docker_image jboss/wildfly
```
See the [*check* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#check-sub-command) wiki page for details.


The expected output for the previous command will be the next one. In this output, **Dagda** responses with the analysis `id`.
```
    {
        "id": "58667994ed253915723c50e7",
        "msg": "Accepted the analysis of <jboss/wildfly>"
    }
```


If you want review a concrete docker analysis, you must type:
```
    python3 dagda.py history <DOCKER_IMAGE_NAME_HERE> --id <REPORT_ID_HERE>
```
For more details about `dagda.py history`, type `python3 dagda.py history --help` or see the [*history* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#history-sub-command) in the wiki page.


The analysis can take several minutes for finishing, so be patient. If you typed the previous command, when you type `python3 dagda.py history jboss/wildfly --id 58667994ed253915723c50e7`, the expected output looks like as shown below.
```
    {
        "id": "58667994ed253915723c50e7",
        "image_name": "jboss/wildfly",
        "status": "Completed",
        "timestamp": "2016-12-14 13:17:12.802486",
        "static_analysis": {
            "os_packages": {
                "total_os_packages": 182,
                "vuln_os_packages": 41,
                "ok_os_packages": 141,
                "os_packages_details": [
                    {
                        "product": "sed",
                        "version": "4.2.2",
                        "is_vulnerable": false,
                        "vulnerabilities": []
                    },
                    {
                        "product": "grep",
                        "version": "2.20",
                        "is_vulnerable": true,
                        "vulnerabilities": [
                            "CVE-2015-1345"
                        ]
                    },
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
                        "is_vulnerable": false,
                        "product": "sqlite",
                        "version": "3.7.17",
                        "vulnerabilities": []
                    }
                ]
            },
            "prog_lang_dependencies": {
                "vuln_dependencies": 9,
                "dependencies_details": {
                    "java": [
                        {
                            "product": "xalan-java",
                            "version": "2.5.2",
                            "vulnerabilities": [
                                "CVE-2014-0107",
                                "BID-30591",
                                "BID-32862",
                                "BID-66397"
                            ]
                        },
                        {
                            "product": "jboss_wildfly_application_server",
                            "version": "-",
                            "vulnerabilities": [
                                "CVE-2014-0018"
                            ]
                        },
                        [...]
                        , {
                            "product": "jboss_weld",
                            "version": "3.0.0",
                            "vulnerabilities": [
                                "CVE-2014-8122",
                                "BID-74252"
                            ]
                        }
                    ],
                    "js": [],
                    "nodejs": [],
                    "php": [],
                    "python": [
                        {
                            "product": "lxml",
                            "version": "1.0.1",
                            "vulnerabilities": [
                                "CVE-2014-3146"
                            ]
                        }
                    ],
                    "ruby": []
                }
            }
        }
    }
```

#### Monitoring running containers for detecting anomalous activities
Another of the main **Dagda** targets is perform the monitoring of runtime docker containers for detecting anomalous activities, so if you want perform the monitoring over a running docker container, you must type:
```
    python3 dagda.py monitor 69dbf26ab368 --start
```
See the [*monitor* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#monitor-sub-command) wiki page for details.


The expected output looks like as shown below:
```
	{
      "id": "586f7631ed25396a829baaf4",
      "image_name": "jboss/wildfly",
      "msg": "Monitoring of docker container with id <69dbf26ab368> started"
	}
```

You can stop the monitoring when you want if you type:
```
    python3 dagda.py monitor 69dbf26ab368 --stop
```

The expected output when you stop the monitoring over a running container looks like as shown below:
```
  {
      "id": "586f7631ed25396a829baaf4",
      "image_name": "jboss/wildfly",
      "timestamp": "2017-01-06 10:49:21.212508",
      "status": "Completed",
      "runtime_analysis": {
          "container_id": "69dbf26ab368",
          "start_timestamp": "2017-01-06 10:49:21.212508",
          "stop_timestamp": "2017-01-06 10:50:16.343847",
          "anomalous_activities_detected": {
              "anomalous_counts_by_severity": {
                  "Warning": 2
              },
              "anomalous_activities_details": [{
                  "output": "10:49:47.492517329: Warning Unexpected setuid call by non-sudo, non-root program (user=<NA> command=ping 8.8.8.8 uid=<NA>) container=thirsty_spence (id=69dbf26ab368)",
                  "priority": "Warning",
                  "rule": "Non sudo setuid",
                  "time": "2017-01-06 10:49:47.492516"
              }, {
                  "output": "10:49:53.181654702: Warning Unexpected setuid call by non-sudo, non-root program (user=<NA> command=ping 8.8.4.4 uid=<NA>) container=thirsty_spence (id=69dbf26ab368)",
                  "priority": "Warning",
                  "rule": "Non sudo setuid",
                  "time": "2017-01-06 10:49:53.181653"
              }]
          }
      }
  }
```

If you want review all your reports, see the [*history*](#history-sub-command) command.

### Bonus Track: Quick Start with Docker

This section describes the installation of **Dagda** using Docker containers, including the Mongo database and a container for **Dagda**, using ```docker-compose```. The docker socket is shared with the **Dagda** container, so it is possible to check docker images and containers from the host where ```docker-compose``` is executed.

Execute the following commands in the root folder of **Dagda** and then, the **Dagda** server will start listening at port 5000:

```
    $ docker-compose build
    $ docker-compose run --service-ports dagda
```

## Troubleshooting

Typically, Dagda works fine, but some scenarios can cause problems. If you get some issue, check the [Troubleshooting](https://github.com/eliasgranderubio/dagda/wiki/Troubleshooting) page for fixing it.

## Change Log

See the [Change Log](https://github.com/eliasgranderubio/dagda/wiki/Change-Log) page for details.

## Bugs and Feedback
For bugs, questions and discussions please use the [Github Issues](https://github.com/eliasgranderubio/dagda/issues) or ping me on Twitter (@3grander).
