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

# to run this test from the command line: python -m tests.authcode_test

import unittest
from authliboclc import authcode


class AuthCodeTests(unittest.TestCase):
    def setUp(self):
        self._authCode = authcode.AuthCode(**{
            'clientId': '1234ABCD',
            'authenticatingInstitutionId': '128807',
            'contextInstitutionId': '128808',
            'redirectUri': 'http://www.oclc.org/test',
            'scopes': ['WMS_NCIP', 'WMS_ACQ']
        })

    def testAuthorizationServer(self):
        self.assertEqual(authcode.AuthCode.authorizationServer, 'https://authn.sd00.worldcat.org/oauth2')

    """ Test Create AuthCode - incorrect parameters should raise exceptions."""

    def testCreateAuthCode(self):
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode()
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': ['WMS_NCIP', 'WMS_ACQ']
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': ['WMS_NCIP', 'WMS_ACQ']
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': ['WMS_NCIP', 'WMS_ACQ']
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'scopes': ['WMS_NCIP', 'WMS_ACQ']
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test'
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': ''
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': []
            })
        with self.assertRaises(authcode.InvalidParameter):
            authcode.AuthCode(**{
                'clientId': '1234ABCD',
                'authenticatingInstitutionId': '128807',
                'contextInstitutionId': '128808',
                'redirectUri': 'http://www.oclc.org/test',
                'scopes': ['']
            })

        myAuthCode = authcode.AuthCode(**{
            'clientId': '1234ABCD',
            'authenticatingInstitutionId': '128807',
            'contextInstitutionId': '128808',
            'redirectUri': 'http://www.oclc.org/test',
            'scopes': ['WMS_NCIP', 'WMS_ACQ']
        })
        self.assertEqual(myAuthCode.clientId, '1234ABCD')
        self.assertEqual(myAuthCode.authenticatingInstitutionId, '128807')
        self.assertEqual(myAuthCode.contextInstitutionId, '128808')
        self.assertEqual(myAuthCode.redirectUri, 'http://www.oclc.org/test')
        self.assertEqual(myAuthCode.scopes[0], 'WMS_NCIP')
        self.assertEqual(myAuthCode.scopes[1], 'WMS_ACQ')

    """ Verify that a proper login url to get the access token is generated."""

    def testGetLoginUrl(self):
        expectedResult = (
            'https://authn.sd00.worldcat.org/oauth2/authorizeCode' +
            '?authenticatingInstitutionId=128807' +
            '&client_id=1234ABCD' +
            '&contextInstitutionId=128808' +
            '&redirect_uri=http%3A%2F%2Fwww.oclc.org%2Ftest' +
            '&response_type=code' +
            '&scope=WMS_NCIP WMS_ACQ'
        )

        self.assertEqual(self._authCode.getLoginUrl(), expectedResult)

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        self.assertEqual(str(self._authCode), (
            '\tauthorizationServer: https://authn.sd00.worldcat.org/oauth2\n' +
            '\tclientId: 1234ABCD\n' +
            '\tauthenticatingInstitutionId: 128807\n' +
            '\tcontextInstitutionId: 128808\n' +
            '\tredirectUri: http://www.oclc.org/test\n' +
            '\tscopes: [\'WMS_NCIP\', \'WMS_ACQ\']\n')
        )


def main():
    unittest.main()


if __name__ == '__main__':
    main()