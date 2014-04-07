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
from authliboclc import accesstoken, refreshtoken
from .. import access_token_formatter


class AccessTokenFormatterTests(unittest.TestCase):
    def setUp(self):
        self._my_access_token_formatter_with_refresh = access_token_formatter.AccessTokenFormatter(
            accesstoken.AccessToken(
                'authorization_code',
                {'scope': ['WMS_NCIP', 'WMS_ACQ'],
                 'authenticating_institution_id': '128807',
                 'context_institution_id': '128808',
                 'redirect_uri': 'ncip://testapp',
                 'refresh_token': refreshtoken.RefreshToken(
                     tokenValue='rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
                     expires_in=1199,
                     expires_at='2014-03-13 15:44:59Z'
                 ),
                 'code': 'unknown'}
            ))

        self._my_access_token_formatter_with_no_refresh = access_token_formatter.AccessTokenFormatter(
            accesstoken.AccessToken(
                'authorization_code',
                {'scope': ['WMS_NCIP', 'WMS_ACQ'],
                 'authenticating_institution_id': '128807',
                 'context_institution_id': '128808',
                 'redirect_uri': 'ncip://testapp',
                 'refresh_token': None,
                 'code': 'unknown'}
            ))


    def testAccessTokenFormatter(self):
        self.assertEqual(self._my_access_token_formatter_with_refresh.format(),
                         '<h2>Access Token</h2><table class="pure-table"><tr><td>access_token</td><td>None</td></tr>' +
                         '<tr><td>token_type</td><td>None</td></tr><tr><td>expires_at</td><td>None</td></tr><tr>' +
                         '<td>expires_in</td><td>None</td></tr>'+
                         '<tr><td>refresh_token</td>' +
                         '<td>rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W</td></tr><tr><td>refresh_token_expires_at</td>' +
                         '<td>2014-03-13 15:44:59Z</td></tr><tr><td>refresh_token_expires_in</td><td>1199</td></tr>' +
                         '</table>')

        self.assertEqual(self._my_access_token_formatter_with_no_refresh.format(),
                         '<h2>Access Token</h2><table class="pure-table"><tr><td>access_token</td><td>None</td></tr>'+
                         '<tr><td>token_type</td><td>None</td></tr><tr><td>expires_at</td><td>None</td></tr><tr>'+
                         '<td>expires_in</td><td>None</td></tr>'+
                         '</table>')


def main():
    unittest.main()


if __name__ == '__main__':
    main()
