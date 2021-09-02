FROM python:3.6.13-buster
# add falco repo
RUN apt update -y
RUN apt install -y apt-transport-https ca-certificates curl gnupg lsb-release apt-utils
RUN curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
RUN echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
RUN echo \
    "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list

RUN apt-get update -y
RUN apt install -y falco linux-headers-amd64 clamav clamav-daemon
RUN freshclam

#RUN curl -sSL https://get.docker.com/ | sh
RUN apt-get install -y docker-ce docker-ce-cli containerd.io

COPY daemon.json /etc/docker/daemon.json

COPY requirements.txt /opt/app/requirements.txt
WORKDIR /opt/app
RUN pip install -r requirements.txt
COPY dagda /opt/app
COPY ./dockerfiles/run.sh /
COPY ./dockerfiles/clamd.conf /etc/clamav/clamd.conf
RUN chmod +x /run.sh
ENTRYPOINT ["/bin/sh","/run.sh"]
