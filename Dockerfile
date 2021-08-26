FROM python:3.8.11-alpine3.14
# add falco repo
RUN apt update -y
RUN apt install -y apt-transport-https ca-certificates curl gnupg lsb-release
RUN curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
RUN echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list

RUN apt-get update -y
RUN apt install -y falco linux-headers-amd64

COPY requirements.txt /opt/app/requirements.txt
WORKDIR /opt/app
RUN pip install -r requirements.txt
COPY dagda /opt/app
COPY ./dockerfiles/run.sh /
COPY ./dockerfiles/clamd.conf /etc/clamav/clamd.conf
RUN chmod +x /run.sh
ENTRYPOINT ["/bin/sh","/run.sh"]
