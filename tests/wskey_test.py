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
from authliboclc import wskey
from authliboclc import authcode
from authliboclc import user


class WskeyTests(unittest.TestCase):
    """ Make sure that valid options aren't changed by accident."""

    """ Create a mock wskey object."""

    def setUp(self):
        self._myWskey = wskey.Wskey(**{
            'key': 'CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM',
            'secret': 'YeZfIJdGYUeatxQOjekRZw==',
            'options': {
                'redirectUri': 'http://www.oclc.org/test',
                'services': [
                    'WMS_NCIP',
                    'WMS_ACQ'
                ]
            }
        })

    """ Verify valid options list is correct."""

    def testValidOptions(self):
        self.assertEqual(wskey.Wskey.validOptions, ['redirectUri', 'services'])

    """ Make sure WSKey creation with invalid parameters raises exceptions. """

    def testCreateWskeyExceptions(self):
        with self.assertRaises(wskey.InvalidObject):
            wskey.Wskey('123ABC', '987', '')
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'services': ['one', 'two']})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirectUri': '', 'services': ['one', 'two']})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirectUri': 'www.mylibrary123.org/myapp', 'services': ['one', 'two']})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirectUri': 'http://www.mylibrary123.org/myapp', 'services': None})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirectUri': 'http://www.mylibrary123.org/myapp', 'services': ''})
        with self.assertRaises(wskey.InvalidParameter):
            wskey.Wskey('123ABC', '987', {'redirectUri': 'http://www.mylibrary123.org/myapp', 'services': []})

    """ Check the parameters of the mock wskey to see if it was created properly. """

    def testCreateWskey(self):
        self.assertEqual(self._myWskey.key,
                         'CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM')
        self.assertEqual(self._myWskey.secret, 'YeZfIJdGYUeatxQOjekRZw==')
        self.assertEqual(self._myWskey.redirectUri, 'http://www.oclc.org/test')
        self.assertEqual(self._myWskey.services, ['WMS_NCIP', 'WMS_ACQ'])

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

        self.assertEqual(self._myWskey.getLoginUrl(**{
            'authenticatingInstitutionId': '128807',
            'contextInstitutionId': '128808'
        }), expectedResult)


    """ Verify that attempts to get an Access Token with invalid parameters raises exceptions"""

    def testGetAccessTokenWithAuthCode(self):
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithAuthCode(**{
                'authenticatingInstitutionId': None,
                'contextInstitutionId': '128808',
                'code': 'unknown',
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithAuthCode(**{
                'authenticatingInstitutionId': '',
                'contextInstitutionId': '128808',
                'code': 'unknown',
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithAuthCode(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': None,
                'code': 'unknown',
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithAuthCode(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '',
                'code': 'unknown',
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithAuthCode(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'code': None,
            })

    """ Verify that attempts to get access token for client credentials grant raises exceptions."""

    def testGetAccessTokenWithClientCredentials(self):
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithClientCredentials(**{
                'authenticatingInstitutionId': None,
                'contextInstitutionId': '12808',
                'user': None
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithClientCredentials(**{
                'authenticatingInstitutionId': '',
                'contextInstitutionId': '12808',
                'user': None
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithClientCredentials(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': None,
                'user': None
            })
        with self.assertRaises(wskey.InvalidParameter):
            self._myWskey.getAccessTokenWithClientCredentials(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '',
                'user': None
            })

    """ Verify that the calculation of an Authentication Header is correct. """

    def testgetHMACSignature(self):
        self._myWskey.debugTimestamp = '1392239490'
        self._myWskey.debugNonce = '0x16577027'

        AuthenticationHeader = self._myWskey.getHMACSignature(**{
            'method': 'GET',
            'requestUrl': ('https://worldcat.org/bib/data/1039085' +
                           '?inst=128807' +
                           '&classificationScheme=LibraryOfCongress' +
                           '&holdingLibraryCode=MAIN'),
            'options': {
                'user': user.User(**{
                    'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
                    'principalIDNS': 'urn:oclc:wms:ad',
                    'authenticatingInstitutionID': '128807'}),
                'authParams': {'userid': 'tasty', 'password': 'buffet'}
            }
        })

        expected = ('http://www.worldcat.org/wskey/v2/hmac/v1 ' +
                    'clientId="CancdeDMjFO9vnzkDrB6WJg1UnyTnkn8lLupLKygr0U1KJLiaAittuVjGRywCDdrsxahv2sbjgKq6hLM",' +
                    'timestamp="1392239490",' +
                    'nonce="0x16577027",' +
                    'signature="+RFPwih61799mpNBJqGhhSbQgd/JRfEinYv81z+CwRY=",' +
                    'password="buffet",' +
                    'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",' +
                    'principalIDNS="urn:oclc:wms:ad",' +
                    'userid="tasty"')

        self.assertEquals(AuthenticationHeader, expected)


    """ Verify the correctness of the hashing algorithm. """

    def testSignRequest(self):
        signature = self._myWskey.signRequest(**{
            'method': 'GET',
            'requestUrl': ('https://worldcat.org/bib/data/1039085' +
                           '?inst=128807' +
                           '&classificationScheme=LibraryOfCongress' +
                           '&holdingLibraryCode=MAIN'),
            'timestamp': '1392239490',
            'nonce': '0x16577027'
        })

        expected = '+RFPwih61799mpNBJqGhhSbQgd/JRfEinYv81z+CwRY='

        self.assertEqual(signature, expected)

    """ Verify that a Normalized Request is generated properly. """

    def testNormalizedRequest(self):
        normalizedRequest = self._myWskey.normalizeRequest(**{
            'method': 'GET',
            'requestUrl': ('https://worldcat.org/bib/data/1039085' +
                           '?inst=128807' +
                           '&classificationScheme=LibraryOfCongress' +
                           '&holdingLibraryCode=MAIN'),
            'timestamp': '1392236038',
            'nonce': '0x66a29eea'})

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

        self.assertEqual(normalizedRequest, expected)

    """ If User and Auth parameters exist, make sure they are added to the Authentication Header. """

    def testAddAuthParams(self):
        myUser = user.User(**{
            'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
            'principalIDNS': 'urn:oclc:wms:ad',
            'authenticatingInstitutionID': '128807'
        })

        authParams = {'userid': 'tasty', 'password': 'buffet'}

        """ Both User and Auth params exists """
        self.assertEqual(self._myWskey.AddAuthParams(**{'user': myUser, 'authParams': authParams}),
                         ('password="buffet",' +
                          'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",' +
                          'principalIDNS="urn:oclc:wms:ad",' +
                          'userid="tasty"'))

        """ Just User params """
        self.assertEqual(self._myWskey.AddAuthParams(**{'user': myUser, 'authParams': None}),
                         'principalID="8eaa9f92-3951-431c-975a-e5dt26b7d232",principalIDNS="urn:oclc:wms:ad"')

        """ Just Auth params """
        self.assertEqual(self._myWskey.AddAuthParams(**{'user': None, 'authParams': authParams}),
                         'password="buffet",userid="tasty"')

        """ Neither User nor Auth params exist."""
        self.assertEqual(self._myWskey.AddAuthParams(**{'user': None, 'authParams': None}), '')


def main():
    unittest.main()


if __name__ == '__main__':
    main()