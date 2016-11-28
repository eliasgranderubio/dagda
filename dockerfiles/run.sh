#!/bin/sh
sed -i 's/localhost/'"$VULNDB_HOST"'/g' /opt/app/etc/checker.conf
python "$@"
