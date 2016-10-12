# -*- coding: utf-8 -*-

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

"""This class represents a refresh token object.

    A refresh token can be returned with an Authentication Token and used to request another token if the authentication
    token is expiring. Refresh tokens are only returned with Authentication Tokens if the services list includes
    'refresh_token'.

"""

import time
import string


class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""

    def __init__(self, message):
        self.message = message


class RefreshToken(object):
    """Class represents a refresh token

    Class Variables:
        refresh_token   string   the refresh token string value
        expires_at      string   the ISO 8601 time that the refresh token expires at
        expires_in      int      the number of seconds until the token expires
    """
    refresh_token = None
    expires_in = None
    expires_at = None

    def __init__(self, tokenValue=None, expires_in=None, expires_at=None):
        """Constructor.

        Args:
            tokenValue: string, the refresh token string value
            expires_at: string, the ISO 8601 time that the refresh token expires at
            expires_in: int, the number of seconds until the token expires
        """
        if tokenValue is None or expires_in is None or expires_at is None:
            raise InvalidParameter('You must pass these parameters: tokenValue, expires_in and expires_at')

        if not isinstance(expires_in, int):
            raise InvalidParameter('expires_in must be an int')

        self.refresh_token = tokenValue
        self.expires_in = expires_in
        self.expires_at = expires_at

    def is_expired(self):
        """ Test if the refresh token is expired

        Returns:
            isExpired: boolean, true if refresh token is expired
        """
        status = False
        if time.mktime(time.strptime(self.expires_at, "%Y-%m-%d %H:%M:%SZ")) < time.time():
            status = True
        return status

    def __str__(self):

        return string.Template("""refresh_token: $refresh_token
expires_in:    $expires_in
expires_at:    $expires_at
""").substitute({
            'refresh_token': self.refresh_token,
            'expires_in': self.expires_in,
            'expires_at': self.expires_at
        })
