FROM python:3.8.11-buster
RUN apt update -y
RUN apt install -y apt-transport-https ca-certificates curl gnupg lsb-release apt-utils
RUN apt-get update -y
RUN apt install -y falco linux-headers-amd64 clamav clamav-daemon
RUN freshclam

COPY requirements.txt /opt/app/requirements.txt
WORKDIR /opt/app
RUN pip install -r requirements.txt
COPY dagda /opt/app
COPY ./dockerfiles/run.sh /
COPY ./dockerfiles/clamd.conf /etc/clamav/clamd.conf
RUN chmod +x /run.sh

ENTRYPOINT ["/bin/sh","/run.sh"]
