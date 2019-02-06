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

        self._authorization_server = 'https://authn.sd00.worldcat.org/oauth2'

        self._my_access_token = accesstoken.AccessToken(self._authorization_server,
                                                        'authorization_code',
                                                        self._options)


    def testAuthorizationServer(self):
        self.assertEqual('https://authn.sd00.worldcat.org/oauth2',
                         self._my_access_token.authorization_server)

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
        valid_grant_types = [
            'authorization_code',
            'refresh_token',
            'client_credentials'
        ]
        self.assertEqual(grant_types, valid_grant_types, 'Grant types must be authorization_code, refresh_token, '
                                                         'client_credentials')

    """ Check that attempts to create Access Tokens work, and incorrect parameters raise exceptions. """

    def testCreateAccessToken(self):
        self.assertEqual(self._my_access_token.scope, ['WMS_NCIP', 'WMS_ACQ'])
        self.assertEqual(self._my_access_token.authenticating_institution_id, '128807')
        self.assertEqual(self._my_access_token.context_institution_id, '128808')
        self.assertEqual(self._my_access_token.redirect_uri, 'ncip://testapp')
        self.assertEqual(self._my_access_token.refresh_token.refresh_token, 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W')
        self.assertEqual(self._my_access_token.code, 'unknown')

        with self.assertRaises(accesstoken.InvalidGrantType):
            accesstoken.AccessToken(authorization_server=self._authorization_server)

        # Tests to make sure there are no missing parameters for authorization_code
        with self.assertRaises(accesstoken.NoOptionsPassed):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='authorization_code',
                                    options={})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='authorization_code',
                                    options={'authenticating_institution_id': '', 'context_institution_id': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='authorization_code',
                                    options={'code': '', 'context_institution_id': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='authorization_code',
                                    options={'code': '', 'authenticating_institution_id': ''})

        # Tests to make sure there are no missing parameters for client_credentials
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='client_credentials',
                                    options={'refresh_token': '',
                                             'context_institution_id': '',
                                             'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='refresh_token',
                                    options={'client_credentials': '',
                                             'authenticating_institution_id': '',
                                             'scope': ''})
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='client_credentials',
                                    options={'refresh_token': '',
                                             'authenticating_institution_id': '',
                                             'context_institution_id': ''})

        # Tests to make sure there are no missing parameters for refresh_token
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='refresh_token',
                                    options={'authenticating_institution_id': '',
                                             'context_institution_id': '',
                                             'scope': ''})

        # Test that scope must be a list of scopes, not a string
        with self.assertRaises(accesstoken.RequiredOptionsMissing):
            accesstoken.AccessToken(authorization_server=self._authorization_server,
                                    grant_type='authorization_code',
                                    options={'code': '',
                                             'redirect_uri': '',
                                             'authenticating_institution_id': '',
                                             'context_institution_id': '',
                                             'scope': 'WMS_ACQ'})

    """ Make sure an expired token is calculated properly. """

    def testIsExpired(self):
        self._my_access_token.expires_at = '2014-01-01 12:00:00Z'
        self.assertTrue(self._my_access_token.is_expired())

        self._my_access_token.expires_at = '2099-01-01 12:00:00Z'
        self.assertFalse(self._my_access_token.is_expired())

    """ Test creation of an access token for authorization_code. """

    def testGetAccessTokenURLforAuthorizationCode(self):
        sample_access_token = accesstoken.AccessToken(self._authorization_server,
                                                      'authorization_code',
                                                      self._options)
        self.assertEqual(sample_access_token.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=authorization_code' +
            '&code=unknown' +
            '&authenticatingInstitutionId=128807' +
            '&contextInstitutionId=128808' +
            '&redirect_uri=ncip%3A%2F%2Ftestapp')
        )

    """ Test creation of an access token for client_credentials. """

    def testGetAccessTokenURLforClientCredentials(self):
        sample_access_token = accesstoken.AccessToken(self._authorization_server,
                                                      'client_credentials',
                                                      self._options)
        self.assertEqual(sample_access_token.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=client_credentials&' +
            'authenticatingInstitutionId=128807&' +
            'contextInstitutionId=128808&' +
            'scope=WMS_NCIP%20WMS_ACQ')
        )

    """ Test creation of an access token for refresh_token. """

    def testGetAccessTokenURLforRefreshToken(self):
        sample_access_token = accesstoken.AccessToken(self._authorization_server,
                                                      'refresh_token',
                                                      self._options)
        self.assertEqual(sample_access_token.get_access_token_url(), (
            'https://authn.sd00.worldcat.org/oauth2/accessToken?' +
            'grant_type=refresh_token' +
            '&refresh_token=rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W'))

    """ Create a mock token response and verify parsing is corrent. """

    def testParseTokenResponse(self):
        sample_access_token = accesstoken.AccessToken(self._authorization_server,
                                                      'authorization_code',
                                                      self._options)
        sample_access_token.parse_token_response(
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
        expected_user = user.User(
            authenticating_institution_id='128807',
            principal_id='2334dd24-b27e-49bd-8fea-7cc8de670f8d',
            principal_idns='urn:oclc:platform:128807'
        )

        expected_refresh_token = refreshtoken.RefreshToken(
            tokenValue='rt_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W',
            expires_in=1900,
            expires_at='2014-03-13 15:44:59Z'
        )

        self.assertEqual(sample_access_token.access_token_string, 'tk_25fXauhJC09E5kwFxcf4TRXkTnaRYWHgJA0W')
        self.assertEqual(sample_access_token.type, 'bearer')
        self.assertEqual(sample_access_token.expires_at, '2014-03-13 15:44:59Z')
        self.assertEqual(sample_access_token.expires_in, 1199)
        self.assertEqual(sample_access_token.error_code, 'trouble')
        self.assertEqual(sample_access_token.context_institution_id, '128807')
        self.assertEqual(user.User, type(sample_access_token.user))
        self.assertEqual(expected_user.authenticating_institution_id,
                         sample_access_token.user.authenticating_institution_id)
        self.assertEqual(expected_user.principal_id, sample_access_token.user.principal_id)
        self.assertEqual(expected_user.principal_idns, sample_access_token.user.principal_idns)
        self.assertEqual(refreshtoken.RefreshToken, type(sample_access_token.refresh_token))
        self.assertEqual(expected_refresh_token.refresh_token, sample_access_token.refresh_token.refresh_token)
        self.assertEqual(expected_refresh_token.expires_in, sample_access_token.refresh_token.expires_in)
        self.assertEqual(expected_refresh_token.expires_at, sample_access_token.refresh_token.expires_at)

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        """Create a new access token which hasn't been authenticated yet."""
        sample_access_token = accesstoken.AccessToken(
            self._authorization_server,
            grant_type='authorization_code',
            options={'scope': ['WMS_NCIP', 'WMS_ACQ'],
                     'authenticating_institution_id': '128807',
                     'context_institution_id': '128808',
                     'redirect_uri': 'https://localhost:8000/auth/',
                     'code': 'unknown'
            }
        )

        """Assume authentication has occured and these parameters are now filled in."""
        sample_access_token.expires_at = '2014-04-08 13:38:29Z'
        sample_access_token.expires_in = 1198
        sample_access_token.access_token_string = 'tk_TBHrsDbSrWW1oS7d3gZr7NJb7PokyOFlf0pr'
        sample_access_token.type = 'bearer'
        sample_access_token.error_code = 404
        sample_access_token.error_message = 'No reply at all.'
        sample_access_token.error_url = 'http://www.noreply.oclc.org/auth/'

        self.assertEqual(str(sample_access_token), (
            "\n" +
            "access_token_url: https://authn.sd00.worldcat.org/oauth2/accessToken?\n" +
            "                  grant_type=authorization_code\n" +
            "                  &code=unknown\n" +
            "                  &authenticatingInstitutionId=128807\n" +
            "                  &contextInstitutionId=128808\n" +
            "                  &redirect_uri=https%3A%2F%2Flocalhost%3A8000%2Fauth%2F\n" +
            "\n" +
            "access_token_string             tk_TBHrsDbSrWW1oS7d3gZr7NJb7PokyOFlf0pr\n" +
            "authenticating_institution_id:  128807\n" +
            "authorization_server:           https://authn.sd00.worldcat.org/oauth2\n" +
            "code:                           unknown\n" +
            "context_institution_id:         128808\n" +
            "error_code:                     404\n" +
            "error_message:                  No reply at all.\n" +
            "error_url:                      http://www.noreply.oclc.org/auth/\n" +
            "expires_at:                     2014-04-08 13:38:29Z\n" +
            "expires_in:                     1198\n" +
            "grant_type:                     authorization_code\n" +
            "options:                        None\n" +
            "redirect_uri:                   https://localhost:8000/auth/\n" +
            "refresh_token:\n" +
            "None\n" +
            "scope:                          ['WMS_NCIP', 'WMS_ACQ']\n" +
            "type:                           bearer\n" +
            "user:\n" +
            "None\n" +
            "wskey:\n" +
            "None")
        )


def main():
    unittest.main()


if __name__ == '__main__':
    main()
