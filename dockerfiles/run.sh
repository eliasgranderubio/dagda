#!/bin/sh
freshclam
service clamav-daemon restart
python dagda.py start -s 0.0.0.0 -p 5000 -m vulndb -mp 27017 --debug
