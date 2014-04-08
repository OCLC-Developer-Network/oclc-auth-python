#!/bin/sh

#
# Run all the tests
#
echo "*****************************"
echo "*** RUNNING LIBRARY TESTS ***"
echo "*****************************"
echo " "
python -m tests.accesstoken_test
python -m tests.authcode_test
python -m tests.refreshtoken_test
python -m tests.user_test
python -m tests.wskey_test

echo "*****************************"
echo "*** RUNNING EXAMPLE TESTS ***"
echo "*****************************"
echo " "
cd ./examples
./runtests.sh
cd ..
