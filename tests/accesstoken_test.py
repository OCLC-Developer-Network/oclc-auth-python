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
from authliboclc import accesstoken
from authliboclc import user
from authliboclc import refreshtoken


class AccessTokenTests(unittest.TestCase):
    _myAccessToken = None;

    """ Create a mock access token. """
    def setUp(self):
        self._options = {'scope': ['WMS_NCIP', 'WMS_ACQ'],
                         'authenticatingInstitutionId': '128807',
                         'contextInstitutionId': '128808',
                         'redirectUri': 'ncip://testapp',
                         'refreshToken': 'tk_1234',
                         'code': 'unknown'}

        self._myAccessToken = accesstoken.AccessToken('authorization_code',
                                                      self._options)

    def testAuthorizationServer(self):
        self.assertEqual('https://authn.sd00.worldcat.org/oauth2',
                         accesstoken.AccessToken.authorizationServer,
                         'Unexpected authorization server endpoint: ' + self._myAccessToken.authorizationServer)

    """ Make sure only the correct valid access token options are listed. """
    def testValidOptions(self):
        options = accesstoken.AccessToken.validOptions
        validOptions = [
            'scope',
            'authenticatingInstitutionId',
            'contextInstitutionId',
            'redirectUri',
            'code',
            'refreshToken'
        ]
        self.assertEqual(options, validOptions,
                         'Options must be scope, authenticatingInstitutionId, contextInstitutionId, redirectUri, '
                         'code and refreshToken')

    """ Make sure the list of valid grant types is correct. """
    def testValidGrantTypes(self):
        grantTypes = accesstoken.AccessToken.validGrantTypes
        validGrantTypes = [
            'authorization_code',
            'refresh_token',
            'client_credentials'
        ]
        self.assertEqual(grantTypes, validGrantTypes, 'Grant types must be authorization_code, refresh_token, '
                                                      'client_credentials')

    """ Check that attempts to create Access Tokens work, and incorrect parameters raise exceptions. """
    def testCreateAccessToken(self):
        self.assertEqual(self._myAccessToken.scope, ['WMS_NCIP', 'WMS_ACQ'])
        self.assertEqual(self._myAccessToken.authenticatingInstitutionId, '128807')
        self.assertEqual(self._myAccessToken.contextInstitutionId, '128808')
        self.assertEqual(self._myAccessToken.redirectUri, 'ncip://testapp')
        self.assertEqual(self._myAccessToken.refreshToken, 'tk_1234')
        self.assertEqual(self._myAccessToken.code, 'unknown')

        with self.assertRaises(accesstoken.InvalidGrantType):
            accesstoken.AccessToken()

        # Tests to make sure there are no missing parameters for authorization_code
        with self.assertRaises(accesstoken.NoOptionsPassed):
            accesstoken.AccessToken('authorization_code', {})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code',
                                    {'authenticatingInstitutionId': '', 'contextInstitutionId': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '', 'contextInstitutionId': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '', 'authenticatingInstitutionId': ''})

        # Tests to make sure there are no missing parameters for client_credentials
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('client_credentials', {'refreshToken': '', 'contextInstitutionId': '', 'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('refresh_token',
                                    {'client_credentials': '', 'authenticatingInstitutionId': '', 'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('client_credentials',
                                    {'refreshToken': '', 'authenticatingInstitutionId': '', 'contextInstitutionId': ''})

        # Tests to make sure there are no missing parameters for refresh_token
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('refresh_token',
                                    {'authenticatingInstitutionId': '', 'contextInstitutionId': '', 'scope': ''})

        # Test that scope must be a list of scopes, not a string
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken('authorization_code', {'code': '',
                                                           'redirectUri': '',
                                                           'authenticatingInstitutionId': '',
                                                           'contextInstitutionId': '',
                                                           'scope': 'WMS_ACQ'})

    """ Make sure an expired token is calculated properly. """
    def testIsExpired(self):
        self._myAccessToken.expiresAt = '2014-01-01 12:00:00Z'
        self.assertTrue(self._myAccessToken.isExpired())

        self._myAccessToken.expiresAt = '2099-01-01 12:00:00Z'
        self.assertFalse(self._myAccessToken.isExpired())

    """ Test creation of an access token for authorization_code. """
    def testGetAccessTokenURLforAuthorizationCode(self):
        myAT = accesstoken.AccessToken('authorization_code', self._options)
        self.assertEqual(myAT.getAccessTokenURL(), (
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
        self.assertEqual(myAT.getAccessTokenURL(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=client_credentials&' +
            'authenticatingInstitutionId=128807&' +
            'contextInstitutionId=128808&' +
            'scope=WMS_NCIP WMS_ACQ')
        )

    """ Test creation of an access token for refresh_token. """
    def testGetAccessTokenURLforRefreshToken(self):
        myAT = accesstoken.AccessToken('refresh_token', self._options)
        self.assertEqual(myAT.getAccessTokenURL(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=refresh_token' +
            '&refresh_token=tk_1234'))

    """ Create a mock token response and verify parsing is corrent. """
    def testParseTokenResponse(self):
        myAT = accesstoken.AccessToken('authorization_code', self._options)
        myAT.parseTokenResponse(
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
            'authenticatingInstitutionID': '128807',
            'principalID': '2334dd24-b27e-49bd-8fea-7cc8de670f8d',
            'principalIDNS': 'urn:oclc:platform:128807'
        })

        expectedRefreshToken = refreshtoken.RefreshToken(**{
            'tokenValue': 'rt_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W',
            'expiresIn': 1900,
            'expiresAt': '2014-03-13 15:44:59Z'
        })

        self.assertEqual(myAT.accessTokenString, 'tk_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W')
        self.assertEqual(myAT.type, 'bearer')
        self.assertEqual(myAT.expiresAt, '2014-03-13 15:44:59Z')
        self.assertEqual(myAT.expiresIn, 1199)
        self.assertEqual(myAT.errorCode, 'trouble')
        self.assertEqual(myAT.contextInstitutionId, '128807')
        self.assertEqual(user.User, type(myAT.user))
        self.assertEqual(expectedUser.authenticatingInstitutionID, myAT.user.authenticatingInstitutionID)
        self.assertEqual(expectedUser.principalID, myAT.user.principalID)
        self.assertEqual(expectedUser.principalIDNS, myAT.user.principalIDNS)
        self.assertEqual(refreshtoken.RefreshToken, type(myAT.refreshToken))
        self.assertEqual(expectedRefreshToken.refreshToken, myAT.refreshToken.refreshToken)
        self.assertEqual(expectedRefreshToken.expiresIn, myAT.refreshToken.expiresIn)
        self.assertEqual(expectedRefreshToken.expiresAt, myAT.refreshToken.expiresAt)


def main():
    unittest.main()


if __name__ == '__main__':
    main()
