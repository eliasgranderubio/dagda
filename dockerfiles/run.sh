#!/bin/sh
freshclam
service clamav-daemon restart
service docker start
sleep 10
python dagda.py start -s 0.0.0.0 -p 5004 -m vulndb -mp 27017 --debug
