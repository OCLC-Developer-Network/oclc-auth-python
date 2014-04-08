#!/bin/sh

#
# Run all the tests for the examples
#
python -m authentication_token.tests.access_token_formatter_test
python -m authentication_token.tests.bibliographic_record_test
python -m authentication_token.tests.server_test
python -m authentication_token.tests.session_handler_test
