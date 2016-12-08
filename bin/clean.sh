#!/bin/bash -e

BASEDIR=`dirname $0`/..

find $BASEDIR -name \*.pyc -delete
rm -rf $BASEDIR/env $BASEDIR/env-test .coverage .cache

