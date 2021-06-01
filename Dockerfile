FROM python:3.6.4-alpine3.6
RUN apk update
RUN apk add linux-headers
COPY requirements.txt /opt/app/requirements.txt
WORKDIR /opt/app
RUN pip install -r requirements.txt
COPY dagda /opt/app
COPY ./dockerfiles/run.sh /
RUN chmod +x /run.sh
ENTRYPOINT ["/bin/sh","/run.sh"]
