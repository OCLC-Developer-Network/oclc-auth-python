#!/bin/sh

#
# Run all the tests
#

python -m tests.accesstoken_test
python -m tests.authcode_test
python -m tests.refreshtoken_test
python -m tests.user_test
python -m tests.wskey_test
