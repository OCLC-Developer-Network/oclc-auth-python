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

# to run this test from the command line: python -m tests.refreshtoken_test

import unittest
from authliboclc import refreshtoken


class RefreshTokenTests(unittest.TestCase):
    _myRefreshToken = None

    """ Create a mock refresh token. """

    def setUp(self):
        self._myRefreshToken = refreshtoken.RefreshToken(**{
            'tokenValue': 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
            'expires_in': 1199,
            'expires_at': '2014-03-13 15:44:59Z',
        })


    """ Test that refresh token creation with invalid parameters raises exceptions."""

    def testCreateRefreshTokenInvalidParameters(self):
        with self.assertRaises(refreshtoken.InvalidParameter):
            refreshtoken.RefreshToken()

        with self.assertRaises(refreshtoken.InvalidParameter):
            refreshtoken.RefreshToken(**{
                'tokenValue': 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
                'expires_in': 1199,
            })
        with self.assertRaises(refreshtoken.InvalidParameter):
            refreshtoken.RefreshToken(**{
                'tokenValue': 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
                'expires_at': '2014-03-13 15:44:59Z',
            })
        with self.assertRaises(refreshtoken.InvalidParameter):
            refreshtoken.RefreshToken(**{
                'expires_in': 1199,
                'expires_at': '2014-03-13 15:44:59Z',
            })
        with self.assertRaises(refreshtoken.InvalidParameter):
            refreshtoken.RefreshToken(**{
                'tokenValue': 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W',
                'expires_in': '1199',
                'expires_at': '2014-03-13 15:44:59Z',
            })

    """ Make sure the parameters are saved properly when the token is created. """

    def testCreateRefreshToken(self):
        self.assertEqual(self._myRefreshToken.refresh_token, 'rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W')
        self.assertEqual(self._myRefreshToken.expires_in, 1199)
        self.assertEqual(self._myRefreshToken.expires_at, '2014-03-13 15:44:59Z')

    """ Test the isExpired calculation."""

    def testIsExpired(self):
        self._myRefreshToken.expires_at = '2014-01-01 12:00:00Z'
        self.assertTrue(self._myRefreshToken.is_expired())

        self._myRefreshToken.expires_at = '2099-01-01 12:00:00Z'
        self.assertFalse(self._myRefreshToken.is_expired())

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        self.assertEqual(str(self._myRefreshToken),
                         'refresh_token: rt_25fXauhJC09E4kwFxcf4TREkTnaRYWHgJA0W\n' +
                         'expires_in:    1199\n' +
                         'expires_at:    2014-03-13 15:44:59Z\n'
        )


def main():
    unittest.main()


if __name__ == '__main__':
    main()