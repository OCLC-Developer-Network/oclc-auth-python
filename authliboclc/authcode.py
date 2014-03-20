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

"""Class represents and authentication code object

HMAC Requests, which are strictly server side, use an Authenication Code object to store their parameters
and perform hashing.

"""
__author__ = 'campbelg@oclc.org (George Campbell)'

from urlparse import urlparse
import urllib

AUTHORIZATION_SERVER = 'https://authn.sd00.worldcat.org/oauth2'


class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""

    def __init__(self, message):
        self.message = message


"""Class begins here"""


class AuthCode(object):
    """Class represents an authentication code object.

    Organizes the parameters and produces a request url so that an authentication code can be obtained
    from OCLC's servers.

    Class Variables:
        authorizationServer           string   the oclc server that conducts authentication
        clientId                      string   the public portion of the Web Services Key (WSKey)
        authenticatingInstitutionId   string   the institutionID that is authenticated against
        contextInstitutionId          string   the institutionID that the request is made against
        redirectUri                   string   the redirectUri for the request
        scopes                        list     a list of one or more web services
    """
    authorizationServer = AUTHORIZATION_SERVER
    clientId = None
    authenticatingInstitutionId = None
    contextInstitutionId = None
    redirectUri = None
    scopes = None

    def __init__(self,
                 clientId=None,
                 authenticatingInstitutionId=None,
                 contextInstitutionId=None,
                 redirectUri=None,
                 scopes=None):
        """Constructor.

        Args:
            clientId: string, the public portion of the Web Services Key (WSKey)
            authenticatingInstitutionId: string, the institutionID that is authenticated against
            contextInstitutionId: string, the institutionID that the request is made against
            redirectUri: string, the redirectUri for the request
            scopes: list, a list of one or more web services
        """

        self.clientId = clientId
        self.authenticatingInstitutionId = authenticatingInstitutionId
        self.contextInstitutionId = contextInstitutionId
        self.redirectUri = redirectUri
        self.scopes = scopes

        if self.clientId == None:
            raise InvalidParameter('Required option missing: clientId.')
        elif self.clientId == '':
            raise InvalidParameter('Cannot be empty string: clientId.')

        if self.authenticatingInstitutionId == None:
            raise InvalidParameter('Required option missing: authenticatingInstitutionId.')
        elif self.authenticatingInstitutionId == '':
            raise InvalidParameter('Cannot be empty string: authenticatingInstitutionId.')

        if self.contextInstitutionId == None:
            raise InvalidParameter('Required option missing: contextInstitutionId.')
        elif self.contextInstitutionId == '':
            raise InvalidParameter('Cannot be empty string: contextInstitutionId.')

        if self.redirectUri == None:
            raise InvalidParameter('Required option missing: redirectUri.')
        elif self.redirectUri == '':
            raise InvalidParameter('Cannot be empty string: redirectUri.')
        else:
            scheme = urlparse("".join(self.redirectUri)).scheme
            if scheme != 'http' and scheme != 'https':
                raise InvalidParameter('Invalid redirectUri. Must begin with http:// or https://')

        if self.scopes == None or self.scopes == '':
            raise InvalidParameter(
                'Required option missing: scopes. Note scopes must be a list of one or more scopes.')
        elif len(self.scopes) == 0 or self.scopes[0] == None or self.scopes[0] == '':
            raise InvalidParameter('You must pass at least one valid scope')


    def getLoginUrl(self):
        """Returns a login url based on the auth code parameters."""
        return (
            AuthCode.authorizationServer + '/authorizeCode' +
            '?' + 'authenticatingInstitutionId=' + self.authenticatingInstitutionId +
            '&' + 'client_id=' + self.clientId +
            '&' + 'contextInstitutionId=' + self.contextInstitutionId +
            '&' + urllib.urlencode({'redirect_uri': self.redirectUri}) +
            '&' + 'response_type=code' +
            '&' + 'scope=' + " ".join(self.scopes)
        )

    def __str__(self):
        ret = ''
        ret += '\tauthorizationServer: ' + str(self.authorizationServer) + "\n"
        ret += '\tclientId: ' + str(self.clientId) + "\n"
        ret += '\tauthenticatingInstitutionId: ' + str(self.authenticatingInstitutionId) + "\n"
        ret += '\tcontextInstitutionId: ' + str(self.contextInstitutionId) + "\n"
        ret += '\tredirectUri: ' + str(self.redirectUri) + "\n"
        ret += '\tscopes: ' + str(self.scopes) + "\n"

        return ret
