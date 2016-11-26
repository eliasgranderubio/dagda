#!/bin/bash -e

BASEDIR=`dirname $0`/..

echo "Testing on python system: `python3 --version`"
TEST_DIR=${BASEDIR}/env-test

echo "$TEST_DIR"
if [ ! -d "$TEST_DIR" ]; then
    virtualenv -p python3 -q $TEST_DIR
    echo "New virtualenv for UT created."

    source $TEST_DIR/bin/activate
    echo "New virtualenv for UT activated."
    pip install -r $BASEDIR/requirements.txt
fi

python3 -m unittest discover -s tests

