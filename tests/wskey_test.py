###############################################################################
# Copyright 2014 OCLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

# to run this test from the command line: python -m tests.wskey_test

import unittest
from authliboclc import wskey, user


class WskeyTests(unittest.TestCase):
    """ Make sure that valid options aren't changed by accident."""

    """ Create a mock wskey object."""

    def setUp(self):
        self._my_wskey = wskey.Wskey(**{
            'key': 'CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM',
            'secret': 'YeZfIJdGYUeatxQOjekRZw==',
            'options': {
                'redirect_uri': 'http://www.oclc.org/test',
                'services': [
                    'WMS_NCIP',
                    'WMS_ACQ'
                ]
            }
        })

    """ Verify valid options list is correct."""

    def testValidOptions(self):
        self.assertEqual(wskey.Wskey.valid_options, ['redirect_uri', 'services'])

    """ Make sure WSKey creation with invalid parameters raises exceptions. """

    def testCreateWskeyExceptions(self):
        with self.assertRaises(wskey.InvalidObject):
            wskey.Wskey('123ABC', '987', '')
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirect_uri': '', 'services': ['one', 'two']})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirect_uri': 'www.mylibrary123.org/myapp', 'services': ['one', 'two']})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirect_uri': 'http://www.mylibrary123.org/myapp', 'services': None})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirect_uri': 'http://www.mylibrary123.org/myapp', 'services': ''})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirect_uri': 'http://www.mylibrary123.org/myapp', 'services': []})

    """ Check the parameters of the mock wskey to see if it was created properly. """

    def testCreateWskey(self):
        self.assertEqual(self._my_wskey.key,
                         'CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM')
        self.assertEqual(self._my_wskey.secret, 'YeZfIJdGYUeatxQOjekRZw==')
        self.assertEqual(self._my_wskey.redirect_uri, 'http://www.oclc.org/test')
        self.assertEqual(self._my_wskey.services, ['WMS_NCIP', 'WMS_ACQ'])

    """ Verify that the generation of a login URL from a WSKey is correct."""

    def testGetLoginUrl(self):
        expectedResult = (
            'https://authn.sd00.worldcat.org/oauth2/authorizeCode?' +
            'authenticatingInstitutionId=128807' +
            '&client_id=CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM' +
            '&contextInstitutionId=128808' +
            '&redirect_uri=http%3A%2F%2Fwww.oclc.org%2Ftest' +
            '&response_type=code' +
            '&scope=WMS_NCIP WMS_ACQ')

        self.assertEqual(self._my_wskey.get_login_url(
            authenticating_institution_id='128807',
            context_institution_id='128808'
        ), expectedResult)


    """ Verify that attempts to get an Access Token with invalid parameters raises exceptions"""

    def testGetAccessTokenWithAuthCode(self):
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_auth_code(
                authenticating_institution_id=None,
                context_institution_id='128808',
                code='unknown',
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_auth_code(
                authenticating_institution_id='',
                context_institution_id='128808',
                code='unknown',
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_auth_code(
                authenticating_institution_id='128807',
                context_institution_id=None,
                code='unknown',
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_auth_code(
                authenticating_institution_id='128807',
                context_institution_id='',
                code='unknown',
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_auth_code(
                authenticating_institution_id='128807',
                context_institution_id='128808',
                code=None,
            )

    """ Verify that attempts to get access token for client credentials grant raises exceptions."""

    def testGetAccessTokenWithClientCredentials(self):
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_client_credentials(
                authenticating_institution_id=None,
                context_institution_id='12808'
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_client_credentials(
                authenticating_institution_id='',
                context_institution_id='12808'
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_client_credentials(
                authenticating_institution_id='128807',
                context_institution_id=None
            )
        with self.assertRaises(wskey.InvalidParameter):
            self._my_wskey.get_access_token_with_client_credentials(
                authenticating_institution_id='128807',
                context_institution_id=''
            )

    """ Verify that the calculation of an Authentication Header is correct. """

    def testget_hmac_signature(self):
        self._my_wskey.debug_time_stamp = '1392239490'
        self._my_wskey.debug_nonce = '0x16577027'

        AuthenticationHeader = self._my_wskey.get_hmac_signature(
            method='GET',
            request_url=('https://worldcat.org/bib/data/1039085' +
                         '?inst=128807' +
                         '&classificationScheme=LibraryOfCongress' +
                         '&holdingLibraryCode=MAIN'),
            options={
                'user': user.User(
                    principal_id='8eaa9f92-3951-431c-975a-e5dt26b7d232',
                    principal_idns='urn:oclc:wms:ad',
                    authenticating_institution_id='128807'),
                'auth_params': {'userid': 'tasty', 'password': 'buffet'}
            }
        )

        expected = ('http://www.worldcat.org/wskey/v2/hmac/v1 ' +
                    'clientID="CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM",' +
                    'timestamp="1392239490",' +
                    'nonce="0x16577027",' +
                    'signature="+RFPwih61799mpNBJqGhhSbQgd/JRfEinYv81z+CwRY=",' +
                    'password="buffet",' +
                    'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",' +
                    'principalIDNS="urn:oclc:wms:ad",' +
                    'userid="tasty"'
        )

        self.assertEqual(AuthenticationHeader, expected)

    """ Verify the correctness of the hashing algorithm. """

    def testSignRequest(self):
        signature = self._my_wskey.sign_request(
            method='GET',
            request_url=('https://worldcat.org/bib/data/1039085' +
                         '?inst=128807' +
                         '&classificationScheme=LibraryOfCongress' +
                         '&holdingLibraryCode=MAIN'),
            timestamp='1392239490',
            nonce='0x16577027'
        )

        expected = '+RFPwih61799mpNBJqGhhSbQgd/JRfEinYv81z+CwRY='

        self.assertEqual(signature, expected)

    """ Verify that a Normalized Request is generated properly. """

    def testNormalizedRequest(self):
        normalized_request = self._my_wskey.normalize_request(
            method='GET',
            request_url=('https://worldcat.org/bib/data/1039085' +
                         '?inst=128807' +
                         '&classificationScheme=LibraryOfCongress' +
                         '&holdingLibraryCode=MAIN'),
            timestamp='1392236038',
            nonce='0x66a29eea')

        expected = ('CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM\n' +
                    '1392236038\n' +
                    '0x66a29eea\n' +
                    '\n' +
                    'GET\n' +
                    'www.oclc.org\n' +
                    '443\n' +
                    '/wskey\n' +
                    'classificationScheme=LibraryOfCongress\n' +
                    'holdingLibraryCode=MAIN\n' +
                    'inst=128807\n')

        self.assertEqual(normalized_request, expected)

    """ Verify that a normalized request is produced correctly if there are no query parameters """

    def testNormalizedRequestWithNoQueryParameters(self):
        normalized_request = self._my_wskey.normalize_request(
            method='GET',
            request_url='https://worldcat.org/bib/data/1039085',
            timestamp='1392236038',
            nonce='0x66a29eea')

        expected = ('CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM\n' +
                    '1392236038\n' +
                    '0x66a29eea\n' +
                    '\n' +
                    'GET\n' +
                    'www.oclc.org\n' +
                    '443\n' +
                    '/wskey\n')

        self.assertEqual(normalized_request, expected)

    """ If User and Auth parameters exist, make sure they are added to the Authentication Header. """

    def testadd_auth_params(self):
        my_user = user.User(
            principal_id='8eaa9f92-3951-431c-975a-e5dt26b7d232',
            principal_idns='urn:oclc:wms:ad',
            authenticating_institution_id='128807'
        )

        auth_params = {'userid': 'tasty', 'password': 'buffet'}

        """ Both User and Auth params exists """
        self.assertEqual(self._my_wskey.add_auth_params(user=my_user, auth_params=auth_params),
                         ('password="buffet",' +
                          'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",' +
                          'principalIDNS="urn:oclc:wms:ad",' +
                          'userid="tasty"'))

        """ Just User params """
        self.assertEqual(self._my_wskey.add_auth_params(user=my_user, auth_params=None),
                         'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",principalIDNS="urn:oclc:wms:ad"')

        """ Just Auth params """
        self.assertEqual(self._my_wskey.add_auth_params(user=None, auth_params=auth_params),
                         'password="buffet",userid="tasty"')

        """ Neither User nor Auth params exist."""
        self.assertEqual(self._my_wskey.add_auth_params(user=None, auth_params=None), '')

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        self.assertEqual(str(self._my_wskey),
                         "key:              CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM\n" +
                         "secret:           YeZfIJdGYUeatxQOjekRZw==\n" +
                         "redirect_uri:     http://www.oclc.org/test\n" +
                         "services:         ['WMS_NCIP', 'WMS_ACQ']\n" +
                         "debug_time_stamp: None\n" +
                         "debug_nonce:      None\n" +
                         "body_hash:        None\n" +
                         "auth_params:      None\n" +
                         "user:\n" +
                         "None")


def main():
    unittest.main()


if __name__ == '__main__':
    main()