#!/bin/bash -e

BASEDIR=`dirname $0`/..

#########################################
# Security tests with Bandit
#########################################

echo -e "\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo    ">> Running security tests...>>"
echo -e ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"

echo "Testing on python system: `python3 --version`"
TEST_DIR=${BASEDIR}/env-test

# Prepare Virtual-env
echo "$TEST_DIR"
if [ ! -d "$TEST_DIR" ]; then
    python3 -m venv $TEST_DIR
    echo "New virtualenv for ST created."

    source $TEST_DIR/bin/activate
    echo "New virtualenv for ST activated."
fi
pip install bandit

# Run security tests
set +e
bandit -r ${BASEDIR}/dagda
set -e

echo -e "\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo    "<< End security tests.      <<"
echo -e "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"

