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

# to run this test from the command line: python -m tests.user_test

import unittest
from authliboclc import user


class UserTests(unittest.TestCase):
    def setUp(self):
        self._user = user.User(**{
            'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
            'principalIDNS': 'urn:oclc:wms:da',
            'authenticatingInstitutionID': '128807'
        })

    """ Test that the creation of the user object incorrect parameters raise exceptions."""

    def testCreateUserExceptions(self):
        with self.assertRaises(user.InvalidParameter):
            user.User()
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalIDNS': 'urn:oclc:wms:da',
                'authenticatingInstitutionID': '128807'
            })
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
                'authenticatingInstitutionID': '128807'
            })
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
                'principalIDNS': 'urn:oclc:wms:da'
            })
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalID': '',
                'principalIDNS': 'urn:oclc:wms:da',
                'authenticatingInstitutionID': '128807'
            })
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
                'principalIDNS': '',
                'authenticatingInstitutionID': '128807'
            })
        with self.assertRaises(user.InvalidParameter):
            user.User(**{
                'principalID': '8eaa9f92-3951-431c-975a-e5dt26b7d232',
                'principalIDNS': 'urn:oclc:wms:da',
                'authenticatingInstitutionID': ''
            })

    """ Make sure that parameters are saved properly for a correctly created user."""

    def testCreateUser(self):
        self.assertEqual(self._user.principalID, '8eaa9f92-3951-431c-975a-e5dt26b7d232')
        self.assertEqual(self._user.principalIDNS, 'urn:oclc:wms:da')
        self.assertEqual(self._user.authenticatingInstitutionID, '128807')

    """Test that the string representation of the class is complete."""

    def testStringRepresenationOfClass(self):
        self.assertEqual(str(self._user), (
            '\tprincipalID:\t\t\t8eaa9f92-3951-431c-975a-e5dt26b7d232\n' +
            '\tprincipalIDNS:\t\t\turn:oclc:wms:da\n' +
            '\tauthenticatingInstitutionID:\t128807\n')
        )


def main():
    unittest.main()


if __name__ == '__main__':
    main()