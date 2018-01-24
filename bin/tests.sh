#!/bin/bash -e

BASEDIR=`dirname $0`/..

#########################################
# Unit tests for Coveralls statistics
#########################################

echo -e "\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo    ">> Running unit tests...    >>"
echo -e ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"

echo "Testing on python system: `python3 --version`"
TEST_DIR=${BASEDIR}/env-test

# Prepare Virtual-env
echo "$TEST_DIR"
if [ ! -d "$TEST_DIR" ]; then
    python3 -m venv $TEST_DIR
    echo "New virtualenv for UT created."

    source $TEST_DIR/bin/activate
    echo "New virtualenv for UT activated."
    pip install -r $BASEDIR/requirements.txt
    pip install requests-mock==1.2.0
    pip install pytest-cov
fi

# Run unit tests
py.test --cov-report term:skip-covered --cov=dagda tests/

echo -e "\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo    "<< End unit tests.          <<"
echo -e "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"

