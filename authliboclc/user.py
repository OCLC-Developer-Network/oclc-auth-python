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

"""Class the represents an OCLC User

A user is authenticated against an institution and a particular set of services. Access is gained with a
principal identifier and principal identifier namespace, along with the authenticating institution's ID.

"""

__author__ = 'campbelg@oclc.org (George Campbell)'


class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""

    def __init__(self, message):
        self.message = message


class User(object):
    """Class represents a user.

    Class variables:

        principalID                   string   the principal identifier
        principalIDNS                 string   the principal identifier namespace
        authenticatingInstitutionId   string   the institutionID that the user is authenticating against
    """
    principalID = None
    principalIDNS = None
    authenticatingInstitutionID = None

    def __init__(self, authenticatingInstitutionID=None, principalID=None, principalIDNS=None):
        """Constructor.

        Args:
            authenticatingInstitutionId: string, the institutionID that the user is authenticating against
            principalID: string, the principal identifier
            principalIDNS: string, the principal identifier namespace
        """
        if authenticatingInstitutionID == None or authenticatingInstitutionID == '':
            raise InvalidParameter('You must set a valid Authenticating Institution ID')
        if principalID == None or principalID == '':
            raise InvalidParameter('You must set a valid principalID')
        if principalIDNS == None or principalIDNS == '':
            raise InvalidParameter('You must set a valid principalIDNS')

        self.authenticatingInstitutionID = authenticatingInstitutionID
        self.principalID = principalID
        self.principalIDNS = principalIDNS

    def __str__(self):
        ret = ''
        ret += '\tprincipalID:\t\t\t' + str(self.principalID) + "\n"
        ret += '\tprincipalIDNS:\t\t\t' + str(self.principalIDNS) + "\n"
        ret += '\tauthenticatingInstitutionID:\t' + str(self.authenticatingInstitutionID) + "\n"
        return ret