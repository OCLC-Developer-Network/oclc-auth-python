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

__author__ = 'campbelg@oclc.org (George Campbell)'

import time
from time import mktime

class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""
    def __init__(self, message):
        self.message = message


class RefreshToken(object):
    """Class represents a refresh token

    Class Variables:
        refreshToken   string   the refresh token string value
        expiresAt      string   the ISO 8601 time that the refresh token expires at
        expiresIn      int      the number of seconds until the token expires
    """
    refreshToken = None
    expiresIn = None
    expiresAt = None

    def __init__(self, tokenValue=None, expiresIn=None, expiresAt=None):
        """Constructor.

        Args:
            tokenValue: string, the refresh token string value
            expiresAt: string, the ISO 8601 time that the refresh token expires at
            expiresIn: int, the number of seconds until the token expires
        """
        if tokenValue == None or expiresIn == None or expiresAt == None:
            raise InvalidParameter('You must pass these parameters: tokenValue, expiresIn and expiresAt')

        if type(expiresIn) is not int:
            raise InvalidParameter('expiresIn must be an int')

        self.refreshToken = tokenValue
        self.expiresIn = expiresIn
        self.expiresAt = expiresAt

    def isExpired(self):
        """ Test if the refresh token is expired

        Returns:
            isExpired: boolean, true if refresh token is expired
        """
        status = False
        if mktime(time.strptime(self.expiresAt, "%Y-%m-%d %H:%M:%SZ")) < time.time():
            status = True
        return status