# -*- coding: utf-8 -*-

# ###############################################################################
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

"""This class represents an access token object.

Contains the parameters and methods to handle access tokens. An access token is received by having the user
authenticate in a web context. Then an authorization code is returned, which is used to retrieve an access
token from OCLC's servers. Calls against web services for a specific insitution and service are then permitted
using the access token, or by using the principalID and principalIDNS returned with the user object portion
of the access token.
"""

__author__ = 'campbelg@oclc.org (George Campbell)'

import time
from time import mktime
from user import User
import urllib
import urllib2
import json
from refreshtoken import RefreshToken

AUTHORIZATION_SERVER = 'https://authn.sd00.worldcat.org/oauth2'

class InvalidGrantType(Exception):
    """Custom exception - an invalid grant type was passed"""

    def __init__(self, message):
        self.message = message


class NoOptionsPassed(Exception):
    """Custom exception - no options were passed"""

    def __init__(self, message):
        self.message = message


class RequiredOptionsMissing(Exception):
    """Custom exception - missing option"""

    def __init__(self, message):
        self.message = message


class InvalidObject(Exception):
    """Custom exception - invalid parameter was passed"""

    def __init__(self, message):
        self.message = message


class AccessToken(object):
    """ Create and manage an OCLC API access token

    Class Variables:

        accessTokenString             string   the value of the access token, ie "at_..."
        accessTokenUrl                string   the url for requesting an access token
        authenticatingInstitutionId   string   the institutionID the user authenticates against
        authorizationServer           string   the url of the OCLC authorization server
        code                          string   the authentication code string
        contextInstitutionId          string   the institutionID the user makes requests against
        errorCode                     int      the code, ie 401, if an access token fails. Normally None.
        errorMessage                  string   the error message associated with the error code. Normally None.
        errorUrl                      string   the request url that had the error
        expiresAt                     string   the ISO 8601 time that the refresh token expires at
        expiresIn                     int      the number of seconds until the token expires
        grantType                     string
        options                       dict:    Valid options are:
                                               - scope
                                               - authenticatingInstitutionId
                                               - contextInstitutionId
                                               - redirectUri
                                               - code
                                               - refreshToken
        redirectUri                   string   string, the url that client authenticates from ie, https://localhost:8000/auth/
        refreshToken                  string   the refresh token object, see refreshtoken.py in the authliboclc folder.
        scope                         list     web services associated with the WSKey, ie ['WorldCatMetadataAPI']
        type                          str      token type, for our use case it is always "bearer"
        user                          object   user object, see user.py in the authliboclc folder.
        wskey                         object   wskey object, see wskey.py in the authliboclc folder.

    """

    accessTokenString = None
    accessTokenUrl = None
    authenticatingInstitutionId = None
    authorizationServer = AUTHORIZATION_SERVER
    code = None
    contextInstitutionId = None
    errorCode = None
    errorMessage = None
    errorUrl = None
    expiresAt = None
    expiresIn = None
    grantType = None
    options = None
    redirectUri = None
    refreshToken = None
    scope = None
    type = None
    user = None
    wskey = None

    validOptions = [
        'scope',
        'authenticatingInstitutionId',
        'contextInstitutionId',
        'redirectUri',
        'code',
        'refreshToken'
    ]

    validGrantTypes = [
        'authorization_code',
        'refresh_token',
        'client_credentials'
    ]


    def __init__(self, grantType=None, options=None):
        """Constructor.

        Args:
            grantType: string, the type of access token request to make:
                       - authorization_code
                       - client_credentials
                       - refresh_token
            options: dict, options depend on the type of request being made, but may include:
                     - scope
                     - authenticatingInstitutionId
                     - contextInstitutionId
                     - redirectUri
                     - code
                     - refreshToken
        """
        if grantType == None or not grantType in AccessToken.validGrantTypes:
            raise InvalidGrantType('You must pass a valid grant type to construct an Access Token.')
        self.grantType = grantType

        if options == None or len(options) < 1:
            raise NoOptionsPassed('You must pass at least one option to construct an Access Token. Valid options '
                                  'are scope, authenticatingInstitutionId, contextInstitutionId, redirectUri, '
                                  'code and refreshToken')

        if (self.grantType == 'authorization_code' and (
                            not 'code' in options or
                            not 'redirectUri' in options or
                        not 'authenticatingInstitutionId' in options or
                    not 'contextInstitutionId' in options)
        ):
            raise RequiredOptionsMissing('You must pass the options: code, redirectUri, '
                                         'authenticatingInstitutionId and contextInstitutionId to construct an Access '
                                         'Token using the authorization_code grant type.')

        elif (self.grantType == 'client_credentials' and (
                            not 'scope' in options or
                            not 'authenticatingInstitutionId' in options or
                        not 'contextInstitutionId' in options or
                    not 'scope' in options)):
            raise RequiredOptionsMissing(
                'You must pass the options: scope, authenticatingInstitutionId and contextInstitutionId ' +
                'to construct an Access Token using the client_credential grant type.')

        elif (self.grantType == 'refresh_token' and (
                not 'refreshToken' in options)):
            raise RequiredOptionsMissing(
                'You must pass the option refreshToken to construct an Access Token using the ' +
                'refresh_token grant type.')

        if ('scope' in options and type(options['scope']) is not list):
            raise RequiredOptionsMissing("scope must be a list of one or more scopes, i.e. ['WMS_NCIP' {, ...}]")

        for key, value in options.items():
            if key in AccessToken.validOptions:
                setattr(self, key, value)

        self.accessTokenUrl = self.getAccessTokenURL()

    def isExpired(self):
        """Test if the token is expired. Returns true if it is."""
        status = False
        if mktime(time.strptime(self.expiresAt, "%Y-%m-%d %H:%M:%SZ")) < time.time():
            status = True
        return status

    def create(self, wskey, user=None):
        """Create an access token."""
        if wskey.__class__.__name__ != 'Wskey':
            raise InvalidObject('A valid Wskey object is required.')
        elif not user == None and not user.__class__.__name__ == 'User':
            raise InvalidObject('A valid User object is required.')
        self.wskey = wskey
        if user != None:
            self.user = user
            self.options = {'user': self.user}
        authorization = self.wskey.getHMACSignature(**{
            'method': 'POST',
            'requestUrl': self.accessTokenUrl,
            'options': self.options
        })
        self.requestAccessToken(authorization, self.accessTokenUrl)

    def refresh(self):
        """Refresh an access token."""
        if self.wskey == None:
            raise InvalidObject('AccessToken must have an associated WSKey Property')

        self.grantType = 'refresh_token'
        self.accessTokenUrl = self.getAccessTokenURL()
        authorization = self.wskey.getHMACSignature(**{
            'method': 'POST',
            'requestUrl': self.accessTokenUrl
        })
        self.requestAccessToken(authorization, self.accessTokenUrl)

    def requestAccessToken(self, authorization, url):
        """ Request an access token. """
        request = urllib2.Request(**{
            'url': url,
            'data': "",
            'headers': {'Authorization': authorization,
                        'Accept': 'application/json'}
        })

        opener = urllib2.build_opener()

        try:
            result = opener.open(request)
            self.parseTokenResponse(result.read())

        except urllib2.HTTPError, e:
            self.parseErrorResponse(e)

    def getAccessTokenURL(self):
        """ get Access Token URL """
        accessTokenUrl = self.authorizationServer + '/accessToken?grant_type=' + self.grantType
        if self.grantType == 'refresh_token':
            accessTokenUrl += '&refresh_token=' + self.refreshToken
        elif self.grantType == 'authorization_code':
            accessTokenUrl += (
                '&' + 'code=' + self.code +
                '&' + 'authenticatingInstitutionId=' + self.authenticatingInstitutionId +
                '&' + 'contextInstitutionId=' + self.contextInstitutionId +
                '&' + urllib.urlencode({'redirect_uri': self.redirectUri}))
        elif self.grantType == 'client_credentials':
            accessTokenUrl += (
                '&authenticatingInstitutionId=' + self.authenticatingInstitutionId +
                '&contextInstitutionId=' + self.contextInstitutionId +
                '&scope=' + ' '.join(self.scope))
        else:
            accessTokenUrl = ''

        return accessTokenUrl


    def parseTokenResponse(self, responseString):
        """Parse the url string which consists of the redirectUri followed by the access token parameters."""
        try:
            responseJSON = json.loads(responseString)
        except ValueError:
            print "ValueError: Unable to decode this Access Token response string to JSON:"
            print responseString
            return

        self.accessTokenString = responseJSON.get('access_token', None)
        self.type = responseJSON.get('token_type', None)
        self.expiresAt = responseJSON.get('expires_at', None)
        self.expiresIn = responseJSON.get('expires_in', None)
        self.contextInstitutionId = responseJSON.get('context_institution_id', None)
        self.errorCode = responseJSON.get('error_code', None)

        principalID = responseJSON.get('principalID', None)
        principalIDNS = responseJSON.get('principalIDNS', None)

        if principalID != None and principalIDNS != None:
            self.user = User(**{
                'authenticatingInstitutionID': self.authenticatingInstitutionId,
                'principalID': principalID,
                'principalIDNS': principalIDNS
            })

        refreshToken = responseJSON.get('refresh_token', None)

        if refreshToken != None:
            self.refreshToken = RefreshToken(**{
                'tokenValue': refreshToken,
                'expiresIn': responseJSON.get('refresh_token_expires_in', None),
                'expiresAt': responseJSON.get('refresh_token_expires_at', None)
            })

    def parseErrorResponse(self, httpError):
        self.errorCode = httpError.getcode()
        self.errorMessage = str(httpError)
        self.errorUrl = httpError.geturl()
        return ''

    def __str__(self):
        ret = 'accessTokenUrl:\t\t\t' + str(self.accessTokenUrl).replace('?', '?\n\t\t\t\t').replace('&',
                                                                                                     '\n\t\t\t\t&') + "\n"
        ret += 'authenticatingInstitutionId:\t' + str(self.authenticatingInstitutionId) + "\n"
        ret += 'authorizationServer:\t\t' + str(self.authorizationServer) + "\n"
        ret += 'code:\t\t\t\t' + str(self.code) + "\n"
        ret += 'contextInstitutionId:\t\t' + str(self.contextInstitutionId) + "\n"
        ret += 'errorCode:\t\t' + str(self.errorCode) + "\n"
        ret += 'errorMessage:\t\t\t' + str(self.errorMessage) + "\n"
        ret += 'expiresAt:\t\t\t' + str(self.expiresAt) + "\n"
        ret += 'expiresIn:\t\t\t' + str(self.expiresIn) + "\n"
        ret += 'grantType:\t\t\t' + str(self.grantType) + "\n"
        ret += 'options:\t\t\t' + str(self.options) + "\n"
        ret += 'redirectUri:\t\t\t' + str(self.redirectUri) + "\n"
        ret += 'refreshToken:' + str(self.refreshToken) + "\n"
        ret += 'scope:\t' + str(self.scope) + "\n"
        ret += 'type:\t\t\t\t' + str(self.type) + "\n"
        ret += 'user:' + str(self.user) + "\n"
        ret += 'wskey:' + str(self.wskey) + "\n"

        return ret