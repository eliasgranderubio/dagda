# Dagda
[![Build Status](https://travis-ci.org/eliasgranderubio/dagda.svg?branch=master)](https://travis-ci.org/eliasgranderubio/dagda)
[![Coverage Status](https://coveralls.io/repos/github/eliasgranderubio/dagda/badge.svg?branch=master)](https://coveralls.io/github/eliasgranderubio/dagda?branch=master)
[![Python](https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg)](https://github.com/eliasgranderubio/dagda)
[![Docker Pulls](https://img.shields.io/docker/pulls/3grander/dagda.svg)](https://hub.docker.com/r/3grander/dagda/)
[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://github.com/eliasgranderubio/dagda)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Feliasgranderubio%2Fdagda.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Feliasgranderubio%2Fdagda?ref=badge_shield)

**Dagda** is a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities.

In order to fulfill its mission, first the known vulnerabilities as CVEs (Common Vulnerabilities and Exposures), BIDs (Bugtraq IDs), RHSAs (Red Hat Security Advisories) and RHBAs (Red Hat Bug Advisories), and the known exploits from Offensive Security database are imported into a MongoDB to facilitate the search of these vulnerabilities and exploits when your analysis are in progress.

Then, when you run a static analysis of known vulnerabilities, **Dagda** retrieves information about the software installed into your docker image, such as the OS packages and the dependencies of the programming languages, and verifies for each product and its version if it is free of vulnerabilities against the previously stored information into the MongoDB. Also, **Dagda** uses [ClamAV](https://www.clamav.net/) as antivirus engine for detecting trojans, viruses, malware & other malicious threats included within the docker images/containers.

**Dagda** supports multiple Linux base images:
  * Red Hat/CentOS/Fedora
  * Debian/Ubuntu
  * OpenSUSE
  * Alpine

**Dagda** rests on [OWASP dependency check](https://github.com/jeremylong/DependencyCheck) + [Retire.js](https://github.com/retirejs/retire.js/) for analyzing multiple dependencies from:
  * java
  * python
  * nodejs
  * js
  * ruby
  * php

On the other hand, **Dagda** is integrated with [Falco](https://falco.org/) for monitoring running docker containers to detect anomalous activities. Also, **Dagda** includes the gathering of real time events from docker daemon.

Finally, each analysis report of a docker image/container, included all static analysis and all runtime monitoring, is stored into the same MongoDB for having available the history of each docker image/container when it is needed.

   * [Requirements](#requirements)
  	 * [Installation of Docker](#installation-of-docker)
     * [Installation of MongoDB](#installation-of-mongodb)
     * [Installation of kernel headers in the host OS](#installation-of-kernel-headers-in-the-host-os)
   * [Usage](#usage)
     * [Populating the database](#populating-the-database)
       * [Database contents](#database-contents)
     * [Analyzing docker images/containers](#analyzing-docker-imagescontainers)
       * [Performing static analysis of known vulnerabilities and other malicious threats](#performing-static-analysis-of-known-vulnerabilities-and-other-malicious-threats)
       * [Monitoring running containers for detecting anomalous activities](#monitoring-running-containers-for-detecting-anomalous-activities)
     * [Getting docker daemon events](#getting-docker-daemon-events)
     * [Bonus Track: Quick Start with Docker](#bonus-track-quick-start-with-docker)
   * [Internal workflows](#internal-workflows)
   * [Troubleshooting](#troubleshooting)
   * [Change Log](#change-log)
   * [Bugs and Feedback](#bugs-and-feedback)
   * [License](#license)

## Requirements
Before **Dagda** usage, you must have installed the next requirements:

* Python 3.4.X or later
* MongoDB 2.6 or later
* Docker
* Pip3
  * PyMongo
  * Requests
  * Python-dateutil
  * Joblib
  * Docker
  * Flask
  * Flask-cors
  * PyYAML
  * Defusedxml
  * Waitress

The requirements can be installed with pip:
```bash
sudo pip3 install -r requirements.txt
```

### Installation of Docker

You must have installed Docker for using **Dagda**. If you need instructions for Docker installation, see the [How-to install Docker](https://docs.docker.com/engine/getstarted/step_one/) page.

In order to avoid having to use `sudo` when you use the `docker` command, create a Unix group called `docker` and add users to it. When the `docker` daemon starts, it makes the ownership of the Unix socket read/writable by the `docker` group.

### Installation of MongoDB

You must have installed MongoDB 2.4 or later for using **Dagda** because in MongoDB are stored both the vulnerabilities/exploits and the analysis results.

If you need instructions for MongoDB installation, see the [How-to install MongoDB Community Edition](https://docs.mongodb.com/manual/administration/install-community/) page.

You can also run MongoDB using docker:
```bash
docker pull mongo
docker run -d -p 27017:27017 mongo
```

### Installation of kernel headers in the host OS

You must have installed the kernel headers in the host OS because **Dagda** is integrated with [Falco](https://falco.org/) for monitoring running docker containers to detect anomalous activities.

This can usually be done on Debian-like distributions with: `apt-get -y install linux-headers-$(uname -r)`

Or, on RHEL-like distributions: `yum -y install kernel-devel-$(uname -r)`

After that, run the command `/usr/lib/dkms/dkms_autoinstaller start` is recommended for avoiding the next Sysdig Falco error trace:
```
rmmod: ERROR: Module sysdig_probe is not currently loaded
```

**Important to note:** In some distributions it has been detected that [Sysdig](http://sysdig.com/) installation is required, so if you need instructions for Sysdig installation, see the [How-to install Sysdig for Linux](https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux) page.

## Usage

You must run `python3 dagda.py start` for starting the **Dagda** server. See the [*start* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#start-sub-command) in the wiki page for details.

After the **Dagda** server started and before the **Dagda** CLI usage, you must set the next environment variables as you need:
```bash
export DAGDA_HOST='127.0.0.1'
export DAGDA_PORT=5000
```

Although in this usage documentation only the CLI usage is shown, **Dagda** has a REST API for using it. See [REST API](https://github.com/eliasgranderubio/dagda/wiki/REST-API) documentation page for details.

### Populating the database

For the initial run, you need to populate the vulnerabilities and the exploits in the database by running:
```bash
python3 dagda.py vuln --init
```
The previous command can take several minutes for finishing so be patient.

If you need repopulating your database for updating with the new vulnerabilities and exploits, you only need rerun the previous command.

Also, you can run queries on your personal database with `dagda.py vuln`. A usage example would be the next one:
```bash
python3 dagda.py vuln --product openldap --product_version 2.2.20
```

The expected output for the previous query is shown below:
```json
    [
        {
            "CVE-2005-4442": {
                "cveid": "CVE-2005-4442",
                "cvss_access_complexity": "Low",
                "cvss_access_vector": "Local access",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "Complete",
                "cvss_base": 7.2,
                "cvss_confidentiality_impact": "Complete",
                "cvss_exploit": 3.9,
                "cvss_impact": 10.0,
                "cvss_integrity_impact": "Complete",
                "cvss_vector": [
                    "AV:L",
                    "AC:L",
                    "Au:N",
                    "C:C",
                    "I:C",
                    "A:C"
                ],
                "cweid": "CWE-0",
                "mod_date": "05-09-2008",
                "pub_date": "20-12-2005",
                "summary": "Untrusted search path vulnerability in OpenLDAP before 2.2.28-r3 on Gentoo Linux allows local users in the portage group to gain privileges via a malicious shared object in the Portage temporary build directory, which is part of the RUNPATH."
            }
        },
        {
            "CVE-2006-2754": {
                "cveid": "CVE-2006-2754",
                "cvss_access_complexity": "Low",
                "cvss_access_vector": "Network",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "None",
                "cvss_base": 5.0,
                "cvss_confidentiality_impact": "None",
                "cvss_exploit": 10.0,
                "cvss_impact": 2.9,
                "cvss_integrity_impact": "Partial",
                "cvss_vector": [
                    "AV:N",
                    "AC:L",
                    "Au:N",
                    "C:N",
                    "I:P",
                    "A:N"
                ],
                "cweid": "CWE-0",
                "mod_date": "07-03-2011",
                "pub_date": "01-06-2006",
                "summary": "Stack-based buffer overflow in st.c in slurpd for OpenLDAP before 2.3.22 might allow attackers to execute arbitrary code via a long hostname."
            }
        },
        {
            "CVE-2006-5779": {
                "cveid": "CVE-2006-5779",
                "cvss_access_complexity": "Low",
                "cvss_access_vector": "Network",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "Partial",
                "cvss_base": 5.0,
                "cvss_confidentiality_impact": "None",
                "cvss_exploit": 10.0,
                "cvss_impact": 2.9,
                "cvss_integrity_impact": "None",
                "cvss_vector": [
                    "AV:N",
                    "AC:L",
                    "Au:N",
                    "C:N",
                    "I:N",
                    "A:P"
                ],
                "cweid": "CWE-399",
                "mod_date": "26-08-2011",
                "pub_date": "07-11-2006",
                "summary": "OpenLDAP before 2.3.29 allows remote attackers to cause a denial of service (daemon crash) via LDAP BIND requests with long authcid names, which triggers an assertion failure."
            }
        },
        {
            "CVE-2006-6493": {
                "cveid": "CVE-2006-6493",
                "cvss_access_complexity": "High",
                "cvss_access_vector": "Network",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "Partial",
                "cvss_base": 5.1,
                "cvss_confidentiality_impact": "Partial",
                "cvss_exploit": 4.9,
                "cvss_impact": 6.4,
                "cvss_integrity_impact": "Partial",
                "cvss_vector": [
                    "AV:N",
                    "AC:H",
                    "Au:N",
                    "C:P",
                    "I:P",
                    "A:P"
                ],
                "cweid": "CWE-0",
                "mod_date": "07-03-2011",
                "pub_date": "12-12-2006",
                "summary": "Buffer overflow in the krbv4_ldap_auth function in servers/slapd/kerberos.c in OpenLDAP 2.4.3 and earlier, when OpenLDAP is compiled with the --enable-kbind (Kerberos KBIND) option, allows remote attackers to execute arbitrary code via an LDAP bind request using the LDAP_AUTH_KRBV41 authentication method and long credential data."
            }
        },
        {
            "CVE-2007-5707": {
                "cveid": "CVE-2007-5707",
                "cvss_access_complexity": "Medium",
                "cvss_access_vector": "Network",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "Complete",
                "cvss_base": 7.1,
                "cvss_confidentiality_impact": "None",
                "cvss_exploit": 8.6,
                "cvss_impact": 6.9,
                "cvss_integrity_impact": "None",
                "cvss_vector": [
                    "AV:N",
                    "AC:M",
                    "Au:N",
                    "C:N",
                    "I:N",
                    "A:C"
                ],
                "cweid": "CWE-399",
                "mod_date": "07-03-2011",
                "pub_date": "30-10-2007",
                "summary": "OpenLDAP before 2.3.39 allows remote attackers to cause a denial of service (slapd crash) via an LDAP request with a malformed objectClasses attribute.  NOTE: this has been reported as a double free, but the reports are inconsistent."
            }
        },
        {
            "CVE-2007-5708": {
                "cveid": "CVE-2007-5708",
                "cvss_access_complexity": "Medium",
                "cvss_access_vector": "Network",
                "cvss_authentication": "None required",
                "cvss_availability_impact": "Complete",
                "cvss_base": 7.1,
                "cvss_confidentiality_impact": "None",
                "cvss_exploit": 8.6,
                "cvss_impact": 6.9,
                "cvss_integrity_impact": "None",
                "cvss_vector": [
                    "AV:N",
                    "AC:M",
                    "Au:N",
                    "C:N",
                    "I:N",
                    "A:C"
                ],
                "cweid": "CWE-399",
                "mod_date": "07-03-2011",
                "pub_date": "30-10-2007",
                "summary": "slapo-pcache (overlays/pcache.c) in slapd in OpenLDAP before 2.3.39, when running as a proxy-caching server, allocates memory using a malloc variant instead of calloc, which prevents an array from being initialized properly and might allow attackers to cause a denial of service (segmentation fault) via unknown vectors that prevent the array from being null terminated."
            }
        },
        {
            "CVE-2011-4079": {
                "cveid": "CVE-2011-4079",
                "cvss_access_complexity": "Low",
                "cvss_access_vector": "Network",
                "cvss_authentication": "Requires single instance",
                "cvss_availability_impact": "Partial",
                "cvss_base": 4.0,
                "cvss_confidentiality_impact": "None",
                "cvss_exploit": 8.0,
                "cvss_impact": 2.9,
                "cvss_integrity_impact": "None",
                "cvss_vector": [
                    "AV:N",
                    "AC:L",
                    "Au:S",
                    "C:N",
                    "I:N",
                    "A:P"
                ],
                "cweid": "CWE-189",
                "mod_date": "06-01-2017",
                "pub_date": "27-10-2011",
                "summary": "Off-by-one error in the UTF8StringNormalize function in OpenLDAP 2.4.26 and earlier allows remote attackers to cause a denial of service (slapd crash) via a zero-length string that triggers a heap-based buffer overflow, as demonstrated using an empty postalAddressAttribute value in an LDIF entry."
            }
        },
        {
            "BID-83610": {
                "bugtraq_id": 83610,
                "class": "Failure to Handle Exceptional Conditions",
                "cve": [
                    "CVE-2006-6493"
                ],
                "local": "no",
                "remote": "yes",
                "title": "OpenLDAP CVE-2006-6493 Remote Security Vulnerability"
            }
        },
        {
            "BID-83843": {
                "bugtraq_id": 83843,
                "class": "Failure to Handle Exceptional Conditions",
                "cve": [
                    "CVE-2006-2754"
                ],
                "local": "no",
                "remote": "yes",
                "title": "OpenLDAP CVE-2006-2754 Remote Security Vulnerability"
            }
        }
    ]
```

For getting all information about a specific CVE, you must run the next command:
```bash
python3 dagda.py vuln --cve_info CVE-2009-2890
```
The expected output for the previous query is shown below:
```json
    [
        {
            "cveid": "CVE-2009-2890",
            "cvss_access_complexity": "Medium",
            "cvss_access_vector": "Network",
            "cvss_authentication": "None required",
            "cvss_availability_impact": "None",
            "cvss_base": 4.3,
            "cvss_confidentiality_impact": "None",
            "cvss_exploit": 8.6,
            "cvss_impact": 2.9,
            "cvss_integrity_impact": "Partial",
            "cvss_vector": [
                "AV:N",
                "AC:M",
                "Au:N",
                "C:N",
                "I:P",
                "A:N"
            ],
            "cweid": "CWE-79",
            "mod_date": "20-08-2009",
            "pub_date": "20-08-2009",
            "summary": "Cross-site scripting (XSS) vulnerability in results.php in PHP Scripts Now Riddles allows remote attackers to inject arbitrary web script or HTML via the searchquery parameter."
        }
    ]
```

If you want to know more details about `dagda.py vuln`, type `python3 dagda.py vuln --help` or see the [*vuln* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#vuln-sub-command) in the wiki page.

#### Database contents

The database is called `vuln_database` and there are 10 collections:

* cve (Common Vulnerabilities and Exposure items) - source NVD NIST
   * cve_info (Extends the information about CVE items)
* bid (BugTraqs Ids items from `http://www.securityfocus.com/`) - source [bidDB_downloader](https://github.com/eliasgranderubio/bidDB_downloader)
   * bid_info (Extends the information about BugTraqs Ids items)
* exploit_db (Offensive Security - Exploit Database) - source [Offensive Security](https://github.com/offensive-security/exploit-database)
   * exploit_db_info (Extends the information about exploits)
* rhba (Red Hat Bug Advisory) - source [OVAL definitions for Red Hat Enterprise Linux 3 and above](https://www.redhat.com/security/data/oval/)
   * rhba_info (Extends the information about RHBAs)
* rhsa (Red Hat Security Advisory) - source [OVAL definitions for Red Hat Enterprise Linux 3 and above](https://www.redhat.com/security/data/oval/)
   * rhsa_info (Extends the information about RHSAs)

### Analyzing docker images/containers

In the next subsections, both, performing static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats and monitoring running docker containers for detecting anomalous activities will be described in depth.

#### Performing static analysis of known vulnerabilities and other malicious threats
One of the main **Dagda** targets is perform the analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers, so if you want perform an analysis over a docker image/container, you must type:
```bash
python3 dagda.py check --docker_image jboss/wildfly
```
See the [*check* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#check-sub-command) wiki page for details.


The expected output for the previous command will be the next one. In this output, **Dagda** responses with the analysis `id`.
```json
    {
        "id": "58667994ed253915723c50e7",
        "msg": "Accepted the analysis of <jboss/wildfly>"
    }
```


Also, if you want run a static analysis in a remote way, you can use the [*agent* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#agent-sub-command):
```bash
python3 dagda.py agent localhost:5000 -i jboss/wildfly
```

The expected output for the previous command will be the next one. In this output, **Dagda** responses with the analysis `id`.
```json
    {
        "id": "58667994ed253915723c50e7",
        "image_name": "jboss/wildfly"
    }
```


If you want review a concrete docker analysis, you must type:
```bash
python3 dagda.py history <DOCKER_IMAGE_NAME_HERE> --id <REPORT_ID_HERE>
```
For more details about `dagda.py history`, type `python3 dagda.py history --help` or see the [*history* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#history-sub-command) in the wiki page.


The analysis can take several minutes for finishing, so be patient. If you typed the previous command, when you type `python3 dagda.py history jboss/wildfly --id 58667994ed253915723c50e7`, the expected output looks like as shown below.
```json
    {
        "id": "58667994ed253915723c50e7",
        "image_name": "jboss/wildfly",
        "status": "Completed",
        "timestamp": "2016-12-14 13:17:12.802486",
        "static_analysis": {
            "malware_binaries": [
                {
                    "file": "/tmp/test/removal-tool.exe",
                    "malware": "Worm.Sober"
                },
                {
                    "file": "/tmp/test/error.hta",
                    "malware": "VBS.Inor.D"
                }
            ],
            "os_packages": {
                "total_os_packages": 182,
                "vuln_os_packages": 41,
                "ok_os_packages": 141,
                "os_packages_details": [
                    {
                        "product": "sed",
                        "version": "4.2.2",
                        "is_vulnerable": false,
                        "is_false_positive": false,
                        "vulnerabilities": []
                    },
                    {
                        "product": "grep",
                        "version": "2.20",
                        "is_vulnerable": true,
                        "is_false_positive": false,
                        "vulnerabilities": [
                            {
                                "CVE-2015-1345": {
                                    "cveid": "CVE-2015-1345",
                                    "cvss_access_complexity": "Low",
                                    "cvss_access_vector": "Local access",
                                    "cvss_authentication": "None required",
                                    "cvss_availability_impact": "Partial",
                                    "cvss_base": 2.1,
                                    "cvss_confidentiality_impact": "None",
                                    "cvss_exploit": 3.9,
                                    "cvss_impact": 2.9,
                                    "cvss_integrity_impact": "None",
                                    "cvss_vector": [
                                        "AV:L",
                                        "AC:L",
                                        "Au:N",
                                        "C:N",
                                        "I:N",
                                        "A:P"
                                    ],
                                    "cweid": "CWE-119",
                                    "mod_date": "23-12-2016",
                                    "pub_date": "12-02-2015",
                                    "summary": "The bmexec_trans function in kwset.c in grep 2.19 through 2.21 allows local users to cause a denial of service (out-of-bounds heap read and crash) via crafted input when using the -F option."
                                }
                            }
                        ]
                    },
                    {
                        "product": "lua",
                        "version": "5.1.4",
                        "is_vulnerable": true,
                        "is_false_positive": false,
                        "vulnerabilities": [
                            {
                                "CVE-2014-5461": {
                                    "cveid": "CVE-2014-5461",
                                    "cvss_access_complexity": "Low",
                                    "cvss_access_vector": "Network",
                                    "cvss_authentication": "None required",
                                    "cvss_availability_impact": "Partial",
                                    "cvss_base": 5.0,
                                    "cvss_confidentiality_impact": "None",
                                    "cvss_exploit": 10.0,
                                    "cvss_impact": 2.9,
                                    "cvss_integrity_impact": "None",
                                    "cvss_vector": [
                                        "AV:N",
                                        "AC:L",
                                        "Au:N",
                                        "C:N",
                                        "I:N",
                                        "A:P"
                                    ],
                                    "cweid": "CWE-119",
                                    "mod_date": "06-01-2017",
                                    "pub_date": "04-09-2014",
                                    "summary": "Buffer overflow in the vararg functions in ldo.c in Lua 5.1 through 5.2.x before 5.2.3 allows context-dependent attackers to cause a denial of service (crash) via a small number of arguments to a function with a large number of fixed arguments."
                                }
                            },
                            {
                                "BID-34237": {
                                    "bugtraq_id": 34237,
                                    "class": "Unknown",
                                    "cve": [],
                                    "local": "no",
                                    "remote": "yes",
                                    "title": "Lua Unspecified Bytecode Verifier Security Vulnerability"
                                }
                            }
                        ]
                    },
                    [...]
                    , {
                        "product": "sqlite",
                        "version": "3.7.17",
                        "is_vulnerable": false,
                        "is_false_positive": false,
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
                            "product_file_path": "/opt/jboss/java/xalan.2.5.2.jar",
                            "is_vulnerable": true,
                            "is_false_positive": false,
                            "vulnerabilities": [
                                {
                                    "CVE-2014-0107": {
                                        "cveid": "CVE-2014-0107",
                                        "cvss_access_complexity": "Low",
                                        "cvss_access_vector": "Network",
                                        "cvss_authentication": "None required",
                                        "cvss_availability_impact": "Partial",
                                        "cvss_base": 7.5,
                                        "cvss_confidentiality_impact": "Partial",
                                        "cvss_exploit": 10.0,
                                        "cvss_impact": 6.4,
                                        "cvss_integrity_impact": "Partial",
                                        "cvss_vector": [
                                            "AV:N",
                                            "AC:L",
                                            "Au:N",
                                            "C:P",
                                            "I:P",
                                            "A:P"
                                        ],
                                        "cweid": "CWE-264",
                                        "mod_date": "06-01-2017",
                                        "pub_date": "15-04-2014",
                                        "summary": "The TransformerFactory in Apache Xalan-Java before 2.7.2 does not properly restrict access to certain properties when FEATURE_SECURE_PROCESSING is enabled, which allows remote attackers to bypass expected restrictions and load arbitrary classes or access external resources via a crafted (1) xalan:content-header, (2) xalan:entities, (3) xslt:content-header, or (4) xslt:entities property, or a Java property that is bound to the XSLT 1.0 system-property function."
                                    }
                                },
                                {
                                    "BID-66397": {
                                        "bugtraq_id": 66397,
                                        "class": "Input Validation Error",
                                        "cve": [
                                            "CVE-2014-0107"
                                        ],
                                        "local": "no",
                                        "remote": "yes",
                                        "title": "Apache Xalan-Java Library CVE-2014-0107 Security Bypass Vulnerability"
                                    }
                                }
                            ]
                        },
                        {
                            "product": "jboss_wildfly_application_server",
                            "version": "-",
                            "product_file_path": "/opt/jboss/java/jboss_wildfly_application_server.jar",
                            "is_vulnerable": true,
                            "is_false_positive": false,
                            "vulnerabilities": [
                                {
                                    "CVE-2014-0018": {
                                        "cveid": "CVE-2014-0018",
                                        "cvss_access_complexity": "Medium",
                                        "cvss_access_vector": "Local access",
                                        "cvss_authentication": "None required",
                                        "cvss_availability_impact": "None",
                                        "cvss_base": 1.9,
                                        "cvss_confidentiality_impact": "None",
                                        "cvss_exploit": 3.4,
                                        "cvss_impact": 2.9,
                                        "cvss_integrity_impact": "Partial",
                                        "cvss_vector": [
                                            "AV:L",
                                            "AC:M",
                                            "Au:N",
                                            "C:N",
                                            "I:P",
                                            "A:N"
                                        ],
                                        "cweid": "CWE-264",
                                        "mod_date": "06-01-2017",
                                        "pub_date": "14-02-2014",
                                        "summary": "Red Hat JBoss Enterprise Application Platform (JBEAP) 6.2.0 and JBoss WildFly Application Server, when run under a security manager, do not properly restrict access to the Modular Service Container (MSC) service registry, which allows local users to modify the server via a crafted deployment."
                                    }
                                }
                            ]
                        },
                        [...]
                        , {
                            "product": "jboss_weld",
                            "version": "3.0.0",
                            "product_file_path": "/opt/jboss/java/jboss_weld.3.0.0.jar",
                            "is_vulnerable": true,
                            "is_false_positive": false,
                            "vulnerabilities": [
                                {
                                    "CVE-2014-8122": {
                                        "cveid": "CVE-2014-8122",
                                        "cvss_access_complexity": "Medium",
                                        "cvss_access_vector": "Network",
                                        "cvss_authentication": "None required",
                                        "cvss_availability_impact": "None",
                                        "cvss_base": 4.3,
                                        "cvss_confidentiality_impact": "Partial",
                                        "cvss_exploit": 8.6,
                                        "cvss_impact": 2.9,
                                        "cvss_integrity_impact": "None",
                                        "cvss_vector": [
                                            "AV:N",
                                            "AC:M",
                                            "Au:N",
                                            "C:P",
                                            "I:N",
                                            "A:N"
                                        ],
                                        "cweid": "CWE-362",
                                        "mod_date": "13-05-2015",
                                        "pub_date": "13-02-2015",
                                        "summary": "Race condition in JBoss Weld before 2.2.8 and 3.x before 3.0.0 Alpha3 allows remote attackers to obtain information from a previous conversation via vectors related to a stale thread state."
                                    }
                                }
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
                            "product_file_path": "/opt/jboss/python/lxml.1.0.1.py",
                            "is_vulnerable": true,
                            "is_false_positive": false,
                            "vulnerabilities": [
                                {
                                    "CVE-2014-3146": {
                                        "cveid": "CVE-2014-3146",
                                        "cvss_access_complexity": "Medium",
                                        "cvss_access_vector": "Network",
                                        "cvss_authentication": "None required",
                                        "cvss_availability_impact": "None",
                                        "cvss_base": 4.3,
                                        "cvss_confidentiality_impact": "None",
                                        "cvss_exploit": 8.6,
                                        "cvss_impact": 2.9,
                                        "cvss_integrity_impact": "Partial",
                                        "cvss_vector": [
                                            "AV:N",
                                            "AC:M",
                                            "Au:N",
                                            "C:N",
                                            "I:P",
                                            "A:N"
                                        ],
                                        "cweid": "CWE-0",
                                        "mod_date": "14-04-2015",
                                        "pub_date": "14-05-2014",
                                        "summary": "Incomplete blacklist vulnerability in the lxml.html.clean module in lxml before 3.3.5 allows remote attackers to conduct cross-site scripting (XSS) attacks via control characters in the link scheme to the clean_html function."
                                    }
                                }
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
Another of the main **Dagda** targets is perform the monitoring of running docker containers for detecting anomalous activities, so if you want perform the monitoring over a running docker container, you must type:
```bash
python3 dagda.py monitor 69dbf26ab368 --start
```
See the [*monitor* sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#monitor-sub-command) wiki page for details.


The expected output looks like as shown below:
```json
    {
        "id": "586f7631ed25396a829baaf4",
        "image_name": "jboss/wildfly",
        "msg": "Monitoring of docker container with id <69dbf26ab368> started"
    }
```

You can stop the monitoring when you want if you type:
```bash
python3 dagda.py monitor 69dbf26ab368 --stop
```

The expected output when you stop the monitoring over a running container looks like as shown below:
```json
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

If you want review all your reports, see the [*history*](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#history-sub-command) command.


### Getting docker daemon events

**Dagda** includes the gathering of real time events from docker daemon, so if you want get all docker daemon events, you must type:
```bash
python3 dagda.py docker events
```

The expected output looks like as shown below:
```json
    [
        {
            "Action": "attach",
                "Actor": {
                    "Attributes": {
                        "build-date": "20171128",
                        "image": "jboss/wildfly",
                        "license": "GPLv2",
                        "name": "amazing_wilson",
                        "vendor": "CentOS"
                    },
                    "ID": "73c5ed015df661ce799baa685a39c32125a47b71f3476e9d452adc381fb8114c"
                },
                "Type": "container",
                "from": "jboss/wildfly",
                "id": "73c5ed015df661ce799baa685a39c32125a47b71f3476e9d452adc381fb8114c",
                "scope": "local",
                "status": "attach",
                "time": 1517323482,
                "timeNano": 1517323482957358115
            },
            {
                "Action": "create",
                "Actor": {
                    "Attributes": {
                        "build-date": "20171128",
                        "image": "jboss/wildfly",
                        "license": "GPLv2",
                        "name": "amazing_wilson",
                        "vendor": "CentOS"
                    },
                    "ID": "73c5ed015df661ce799baa685a39c32125a47b71f3476e9d452adc381fb8114c"
                },
                "Type": "container",
                "from": "jboss/wildfly",
                "id": "73c5ed015df661ce799baa685a39c32125a47b71f3476e9d452adc381fb8114c",
                "scope": "local",
                "status": "create",
                "time": 1517323482,
                "timeNano": 1517323482944595092
        }
    ]
```

If you want review all allowed filters for this command, see the [*docker*](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#docker-sub-command) command.


### Bonus Track: Quick Start with Docker

This section describes the installation of **Dagda** using Docker containers, including the Mongo database and a container for **Dagda**, using ```docker-compose```. The docker socket is shared with the **Dagda** container, so it is possible to check docker images and containers from the host where ```docker-compose``` is executed.

Execute the following commands in the root folder of **Dagda** and then, the **Dagda** server will start listening at port 5000:

```bash
docker-compose build
docker-compose up -d
```

## Internal workflows

Below, a 10,000 foot diagram about the **Dagda** internal workflows is shown:

![Dagda_internal_workflows](https://raw.githubusercontent.com/eliasgranderubio/dagda/master/img/Dagda_internal_workflows.png)

## Troubleshooting

Typically, **Dagda** works fine, but some scenarios can cause problems. If you get some issue, check the [Troubleshooting](https://github.com/eliasgranderubio/dagda/wiki/Troubleshooting) page for fixing it.

## Change Log

See the [Change Log](https://github.com/eliasgranderubio/dagda/wiki/Change-Log) page for details.

## Bugs and Feedback
For bugs, questions and discussions please use the [Github Issues](https://github.com/eliasgranderubio/dagda/issues) or ping me on Twitter (@3grander).


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Feliasgranderubio%2Fdagda.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Feliasgranderubio%2Fdagda?ref=badge_large)
