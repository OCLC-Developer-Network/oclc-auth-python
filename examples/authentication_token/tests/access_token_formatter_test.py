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

# to run this test from the command line: python -m tests.access_token_formatter_test

import unittest
from authliboclc import accesstoken, refreshtoken, user
from .. import access_token_formatter


class AccessTokenFormatterTests(unittest.TestCase):
    def setUp(self):

        """Create a new access token which hasn't been authenticated yet."""
        self._access_token = accesstoken.AccessToken(
            authorization_server='https://authn.sd00.worldcat.org/oauth2',
            grant_type='authorization_code',
            options={'scope': ['WMS_NCIP', 'WMS_ACQ'],
                     'authenticating_institution_id': '128807',
                     'context_institution_id': '128808',
                     'redirect_uri': 'https://localhost:8000/auth/',
                     'code': 'unknown'
            }
        )

        """Assume authentication has occured and these parameters are now filled in."""
        self._access_token.expires_at = '2014-04-08 13:38:29Z'
        self._access_token.expires_in = 1198
        self._access_token.access_token_string = 'tk_TBHrsDbSrWW1oS7d3gZr7NJb7PokyOFlf0pr'
        self._access_token.type = 'bearer'
        self._access_token.refresh_token = refreshtoken.RefreshToken(
            tokenValue='rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
            expires_in=1199,
            expires_at='2014-03-13 15:44:59Z'
        )

        self._my_access_token_formatter = access_token_formatter.AccessTokenFormatter(
            access_token=self._access_token
        )


    """Test the display of an access_token without the user properties set."""
    def testAccessTokenFormatter(self):
        self.assertEqual(self._my_access_token_formatter.format(),
                         '<h2>Access Token</h2>' +
                         '<table class="pure-table">' +
                         '<tr><td>access_token</td><td>tk_TBHrsDbSrWW1oS7d3gZr7NJb7PokyOFlf0pr</td></tr>' +
                         '<tr><td>token_type</td><td>bearer</td></tr>' +
                         '<tr><td>expires_at</td><td>2014-04-08 13:38:29Z</td></tr>' +
                         '<tr><td>expires_in</td><td>1198</td></tr>' +
                         '<tr><td>refresh_token</td><td>rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W</td></tr>' +
                         '<tr><td>refresh_token_expires_at</td><td>2014-03-13 15:44:59Z</td></tr>' +
                         '<tr><td>refresh_token_expires_in</td><td>1199</td></tr>' +
                         '</table>')

    """Test the display of an access_token with the user properties set."""
    def testAccessTokenFormatterWithUser(self):
        self._access_token.user = user.User(
            authenticating_institution_id='128807',
            principal_id='2334ed24-b27e-63bd-8fea-7cw2deq70r8d',
            principal_idns='urn:oclc:platform:128807')

        self.assertEqual(self._my_access_token_formatter.format(),
                         '<h2>Access Token</h2>' +
                         '<table class="pure-table">' +
                         '<tr><td>access_token</td><td>tk_TBHrsDbSrWW1oS7d3gZr7NJb7PokyOFlf0pr</td></tr>' +
                         '<tr><td>token_type</td><td>bearer</td></tr>' +
                         '<tr><td>expires_at</td><td>2014-04-08 13:38:29Z</td></tr>' +
                         '<tr><td>expires_in</td><td>1198</td></tr>' +
                         '<tr><td>principalID</td><td>2334ed24-b27e-63bd-8fea-7cw2deq70r8d</td></tr>' +
                         '<tr><td>principalIDNS</td><td>urn:oclc:platform:128807</td></tr>' +
                         '<tr><td>contextInstitutionId</td><td>128808</td></tr>' +
                         '<tr><td>refresh_token</td><td>rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W</td></tr>' +
                         '<tr><td>refresh_token_expires_at</td><td>2014-03-13 15:44:59Z</td></tr>' +
                         '<tr><td>refresh_token_expires_in</td><td>1199</td></tr>' +
                         '</table>')

    """Test the display of an access_token without the error properties set."""
    def testAccessTokenFormatterWithError(self):
        self._access_token.error_code = '500'
        self._access_token.error_message = 'No Reply at All'
        self._access_token.error_url = 'http://www.nobody-is-ho.me'

        self.assertEqual(self._my_access_token_formatter.format(),
                         '<h2>Access Token</h2>' +
                         '<table class="pure-table">' +
                         '<tr><td>Error Code</td><td>500</td></tr>' +
                         '<tr><td>Error Message</td><td>No Reply at All</td></tr>' +
                         '<tr><td>Error Url</td><td><pre>http://www.nobody-is-ho.me</pre></td></tr>' +
                         '</table>')

def main():
    unittest.main()


if __name__ == '__main__':
    main()
