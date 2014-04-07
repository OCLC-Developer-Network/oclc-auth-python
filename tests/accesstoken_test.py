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

# to run this test from the command line: python -m tests.accesstoken_test

import unittest
from authliboclc import accesstoken, user, refreshtoken


class AccessTokenTests(unittest.TestCase):
    """ Create a mock access token. """

    def setUp(self):
        self._my_refresh_token = refreshtoken.RefreshToken(
            tokenValue='rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
            expires_in=1199,
            expires_at='2014-03-13 15:44:59Z'
        )

        self._options = {'scope': ['WMS_NCIP', 'WMS_ACQ'],
                         'authenticating_institution_id': '128807',
                         'context_institution_id': '128808',
                         'redirect_uri': 'ncip://testapp',
                         'refresh_token': self._my_refresh_token,
                         'code': 'unknown'}

        self._myAccessToken = accesstoken.AccessToken('authorization_code',
                                                      self._options)

    def testAuthorizationServer(self):
        self.assertEqual('https://authn.sd00.worldcat.org/oauth2',
                         accesstoken.AccessToken.authorization_server,
                         'Unexpected authorization server endpoint: ' + self._myAccessToken.authorization_server)

    """ Make sure only the correct valid access token options are listed. """

    def testValidOptions(self):
        options = accesstoken.AccessToken.valid_options
        valid_options = [
            'scope',
            'authenticating_institution_id',
            'context_institution_id',
            'redirect_uri',
            'code',
            'refresh_token'
        ]
        self.assertEqual(options, valid_options,
                         'Options must be scope, authenticating_institution_id, context_institution_id, redirect_uri, '
                         'code and refresh_token')

    """ Make sure the list of valid grant types is correct. """

    def testValidGrantTypes(self):
        grant_types = accesstoken.AccessToken.validGrantTypes
        validGrantTypes = [
            'authorization_code',
            'refresh_token',
            'client_credentials'
        ]
        self.assertEqual(grant_types, validGrantTypes, 'Grant types must be authorization_code, refresh_token, '
                                                       'client_credentials')

    """ Check that attempts to create Access Tokens work, and incorrect parameters raise exceptions. """

    def testCreateAccessToken(self):
        self.assertEqual(self._myAccessToken.scope, ['WMS_NCIP', 'WMS_ACQ'])
        self.assertEqual(self._myAccessToken.authenticating_institution_id, '128807')
        self.assertEqual(self._myAccessToken.context_institution_id, '128808')
        self.assertEqual(self._myAccessToken.redirect_uri, 'ncip://testapp')
        self.assertEqual(self._myAccessToken.refresh_token.refresh_token, 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W')
        self.assertEqual(self._myAccessToken.code, 'unknown')

        with self.assertRaises(accesstoken.InvalidGrantType):
            accesstoken.AccessToken()

        # Tests to make sure there are no missing parameters for authorization_code
        with self.assertRaises(accesstoken.NoOptionsPassed):
            accesstoken.AccessToken('authorization_code', {})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code',
                                    {'authenticating_institution_id': '', 'context_institution_id': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '', 'context_institution_id': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '', 'authenticating_institution_id': ''})

        # Tests to make sure there are no missing parameters for client_credentials
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('client_credentials',
                                    {'refresh_token': '', 'context_institution_id': '', 'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('refresh_token',
                                    {'client_credentials': '', 'authenticating_institution_id': '', 'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('client_credentials',
                                    {'refresh_token': '', 'authenticating_institution_id': '',
                                     'context_institution_id': ''})

        # Tests to make sure there are no missing parameters for refresh_token
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('refresh_token',
                                    {'authenticating_institution_id': '', 'context_institution_id': '', 'scope': ''})

        # Test that scope must be a list of scopes, not a string
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '',
                                                           'redirect_uri': '',
                                                           'authenticating_institution_id': '',
                                                           'context_institution_id': '',
                                                           'scope': 'WMS_ACQ'})

    """ Make sure an expired token is calculated properly. """

    def testIsExpired(self):
        self._myAccessToken.expires_at = '2014-01-01 12:00:00Z'
        self.assertTrue(self._myAccessToken.is_expired())

        self._myAccessToken.expires_at = '2099-01-01 12:00:00Z'
        self.assertFalse(self._myAccessToken.is_expired())

    """ Test creation of an access token for authorization_code. """

    def testGetAccessTokenURLforAuthorizationCode(self):
        myAT = accesstoken.AccessToken('authorization_code', self._options)
        self.assertEqual(myAT.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=authorization_code' +
            '&code=unknown' +
            '&authenticatingInstitutionId=128807' +
            '&contextInstitutionId=128808' +
            '&redirect_uri=ncip%3A%2F%2Ftestapp')
        )

    """ Test creation of an access token for client_credentials. """

    def testGetAccessTokenURLforClientCredentials(self):
        myAT = accesstoken.AccessToken('client_credentials', self._options)
        self.assertEqual(myAT.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=client_credentials&' +
            'authenticatingInstitutionId=128807&' +
            'contextInstitutionId=128808&' +
            'scope=WMS_NCIP WMS_ACQ')
        )

    """ Test creation of an access token for refresh_token. """

    def testGetAccessTokenURLforRefreshToken(self):
        myAT = accesstoken.AccessToken('refresh_token', self._options)
        self.assertEqual(myAT.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=refresh_token' +
            '&refresh_token=rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W'))

    """ Create a mock token response and verify parsing is corrent. """

    def testParseTokenResponse(self):
        myAT = accesstoken.AccessToken('authorization_code', self._options)
        myAT.parse_token_response(
            '{' +
            '"expires_at":"2014-03-13 15:44:59Z",' +
            '"principalIDNS":"urn:oclc:platform:128807",' +
            '"principalID":"2334dd24-b27e-49bd-8fea-7cc8de670f8d",' +
            '"error_code":"trouble",' +
            '"expires_in":1199,' +
            '"token_type":"bearer",' +
            '"context_institution_id":"128807",' +
            '"access_token":"tk_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W",' +
            '"refresh_token":"rt_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W",' +
            '"refresh_token_expires_in":1900,' +
            '"refresh_token_expires_at":"2014-03-13 15:44:59Z"' +
            '}'

        )
        expectedUser = user.User(**{
            'authenticating_institution_id': '128807',
            'principal_id': '2334dd24-b27e-49bd-8fea-7cc8de670f8d',
            'principal_idns': 'urn:oclc:platform:128807'
        })

        expectedRefreshToken = refreshtoken.RefreshToken(**{
            'tokenValue': 'rt_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W',
            'expires_in': 1900,
            'expires_at': '2014-03-13 15:44:59Z'
        })

        self.assertEqual(myAT.access_token_string, 'tk_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W')
        self.assertEqual(myAT.type, 'bearer')
        self.assertEqual(myAT.expires_at, '2014-03-13 15:44:59Z')
        self.assertEqual(myAT.expires_in, 1199)
        self.assertEqual(myAT.error_code, 'trouble')
        self.assertEqual(myAT.context_institution_id, '128807')
        self.assertEqual(user.User, type(myAT.user))
        self.assertEqual(expectedUser.authenticating_institution_id, myAT.user.authenticating_institution_id)
        self.assertEqual(expectedUser.principal_id, myAT.user.principal_id)
        self.assertEqual(expectedUser.principal_idns, myAT.user.principal_idns)
        self.assertEqual(refreshtoken.RefreshToken, type(myAT.refresh_token))
        self.assertEqual(expectedRefreshToken.refresh_token, myAT.refresh_token.refresh_token)
        self.assertEqual(expectedRefreshToken.expires_in, myAT.refresh_token.expires_in)
        self.assertEqual(expectedRefreshToken.expires_at, myAT.refresh_token.expires_at)

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        self.assertEqual(str(self._myAccessToken), (
            'access_token_url:\t\t\thttps://authn.sd00.worldcat.org/oauth2/accessToken?\n' +
            '\t\t\t\tgrant_type=authorization_code\n' +
            '\t\t\t\t&code=unknown\n' +
            '\t\t\t\t&authenticatingInstitutionId=128807\n' +
            '\t\t\t\t&contextInstitutionId=128808\n' +
            '\t\t\t\t&redirect_uri=ncip%3A%2F%2Ftestapp\n' +
            'authenticating_institution_id:\t128807\n' +
            'authorization_server:\t\thttps://authn.sd00.worldcat.org/oauth2\n' +
            'code:\t\t\t\tunknown\n' +
            'context_institution_id:\t\t128808\n' +
            'error_code:\t\tNone\n' +
            'error_message:\t\t\tNone\n' +
            'expires_at:\t\t\tNone\n' +
            'expires_in:\t\t\tNone\n' +
            'grant_type:\t\t\tauthorization_code\n' +
            'options:\t\t\tNone\n' +
            'redirect_uri:\t\t\tncip://testapp\n' +
            'refresh_token:\trefresh_token:\trt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W\n' +
            '\t\texpires_in:\t1199\n' +
            '\t\texpires_at:\t2014-03-13 15:44:59Z\n' +
            '\n' + 'scope:\t[\'WMS_NCIP\', \'WMS_ACQ\']\n' +
            'type:\t\t\t\tNone\n' +
            'user:None\n' +
            'wskey:None\n')
        )


def main():
    unittest.main()


if __name__ == '__main__':
    main()
