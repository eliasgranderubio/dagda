# check_docker_image
**check_docker_image** is a tool to perform static analysis of known vulnerabilities in docker images/containers.

To fulfill its mission, the CVEs (Common Vulnerabilities and Exposures) are imported into a MongoDB to facilitate search and processing of these CVEs.

Finally, each docker image scan result is stored into the same MongoDB for be capable of retrieve the vulnerabilities history of each docker image/container when you need.

## Requirements
Before **check_docker_image** usage, you must have installed Python >= 3.4.5 and the requirements:

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

### Installation of MongoDB

You must have installed MongoDB 2.4 or later for using **check_docker_image** because in MongoDB are stored both the CVE vulnerabilities and the docker image scan results.

If you need instructions for MongoDB installation, see the [How-to install MongoDB Community Edition](https://docs.mongodb.com/manual/administration/install-community/) page.

You can also run MongoDB using docker:
```
    docker run -d -p 27017:27017 mongo
```

### Installation of Docker

You must have installed Docker for using **check_docker_image**. If you need instructions for Docker installation, see the [How-to install Docker](https://docs.docker.com/engine/getstarted/step_one/) page.

To avoid having to use `sudo` when you use the `docker` command, create a Unix group called `docker` and add users to it. When the `docker` daemon starts, it makes the ownership of the Unix socket read/writable by the `docker` group.

## Populating the database

For the initial run, you need to populate the CVE database by running:
```
    python3 cve_db.py --init
```

If you need repopulating your database for update with the new CVEs, you only need rerun the previous command.

Also, you can run queries on your personal CVE database with this tool. Below, the help when you type `python3 cve_db.py -h` is shown:
```
    usage: cve_db.py [-h] [--init] [--cve CVE] [--product PRODUCT]
                     [--product_version PRODUCT_VERSION] [--only_check] [-v]

    Your personal CVE database.

    optional arguments:
      -h, --help            show this help message and exit
      --init                initialize your local database with all CVEs provided
                            by NIST publications. If this argument is present,
                            first all CVEs of your local database will be removed
                            and inserted again with all CVEs provided by NIST
                            publications
      --cve CVE             all products with this CVE vulnerability will be shown
      --product PRODUCT     all CVE vulnerabilities of this product will be shown
      --product_version PRODUCT_VERSION
                            extra filter for product query about its CVE
                            vulnerabilities. If this argument is present, the "--
                            product" argument must be present too
      --only_check          only checks if "--product" with "--product_version"
                            has CVE vulnerabilities but they will not be shown
      -v, --version         show the version message and exit
```

Fulfilling with the described usage, a usage example would be the next one (Keep in mind that `--product_version` is a optional argument)
```
    python3 cve_db.py --product openldap --product_version 2.2.20
```

The expected output is shown below:
```
    [
		"CVE-2005-4442", 
		"CVE-2006-6493", 
		"CVE-2006-5779", 
		"CVE-2006-2754", 
		"CVE-2007-5707", 
		"CVE-2007-5708", 
		"CVE-2011-4079"
	]
```

## Usage
**IMPORTANT NOTE:** In this **check_docker_image** version, the `docker pull` command must be run out-of-the-box because this functionality is not included. That is way, the docker image must be in the host when you run `check_docker_image`.

Below, the help when you type `python3 check_docker_image.py --help` is shown:

```
    usage: check_docker_image.py [-h] [-i DOCKER_IMAGE] [-c CONTAINER_ID]
                                 [--show_history] [-v]

    Your personal docker image security scanner.

    optional arguments:
      -h, --help            show this help message and exit
      -i DOCKER_IMAGE, --docker_image DOCKER_IMAGE
                            the input docker image name
      -c CONTAINER_ID, --container_id CONTAINER_ID
                            the input docker container id
      --show_history        the security scan history for the requested docker
                            image will be shown order by date from the newest to
                            oldest
      -v, --version         show the version message and exit
```

Fulfilling with the described usage, a usage example would be the next one (note that the expected output has been shortened):
```
	python3 check_docker_image.py --docker_image jboss/wildfly
```

The expected output is shown below:
```
    {
        "total_products": 182,
        "ok_products": 161,
        "vuln_products": 21,
        "image_name": "jboss/wildfly",
        "timestamp": "2016-11-15 19:57:57.548829",
        "evaluated_packages_info": [{
            "product": "sed",
            "status": "OK",
            "version": "4.2.2"
        }, {
            "product": "grep",
            "status": "VULN",
            "version": "2.20"
        }, {
            "product": "lua",
            "status": "VULN",
            "version": "5.1.4"
        },
        [...]
        , {
            "product": "sqlite",
            "status": "OK",
            "version": "3.7.17"
        }]
    }
```

## Bugs and Feedback
For bugs, questions and discussions please use the [Github Issues](https://github.com/eliasgranderubio/check_docker_image/issues) or ping me on Twitter (@3grander).
