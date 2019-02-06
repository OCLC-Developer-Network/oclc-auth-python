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
using the access token, or by using the principal_id and principal_idns returned with the user object portion
of the access token.
"""

import json
import string
import time

import six

from .user import User
from .refreshtoken import RefreshToken


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

        access_token_string            string   the value of the access token, ie "at_..."
        access_token_url               string   the url for requesting an access token
        authenticating_institution_id  string   the institutionID the user authenticates against
        authorization_server           string   the url of the OCLC authorization server
        code                           string   the authentication code string
        context_institution_id         string   the institutionID the user makes requests against
        error_code                     int      the code, ie 401, if an access token fails. Normally None.
        error_message                  string   the error message associated with the error code. Normally None.
        error_url                      string   the request url that had the error
        expires_at                     string   the ISO 8601 time that the refresh token expires at
        expires_in                     int      the number of seconds until the token expires
        grant_type                     string
        options                        dict:    Valid options are:
                                                - scope
                                                - authenticating_institution_id
                                                - context_institution_id
                                                - redirect_uri
                                                - code
                                                - refresh_token
        redirect_uri                   string   string, the url that client authenticates from ie, https://localhost:8000/auth/
        refresh_token                  string   the refresh token object, see refreshtoken.py in the authliboclc folder.
        scope                          list     web services associated with the WSKey, ie ['WorldCatMetadataAPI']
        type                           str      token type, for our use case it is always "bearer"
        user                           object   user object, see user.py in the authliboclc folder.
        wskey                          object   wskey object, see wskey.py in the authliboclc folder.
    """

    access_token_string = None
    access_token_url = None
    authenticating_institution_id = None
    authorization_server = None
    code = None
    context_institution_id = None
    error_code = None
    error_message = None
    error_url = None
    expires_at = None
    expires_in = None
    grant_type = None
    options = None
    redirect_uri = None
    refresh_token = None
    scope = None
    type = None
    user = None
    wskey = None

    valid_options = [
        'scope',
        'authenticating_institution_id',
        'context_institution_id',
        'redirect_uri',
        'code',
        'refresh_token'
    ]

    validGrantTypes = [
        'authorization_code',
        'refresh_token',
        'client_credentials'
    ]

    def __init__(self, authorization_server, grant_type=None, options=None):
        """Constructor.

        Args:
            authorization_server: string, url of the authorization server
            grant_type: string, the type of access token request to make:
                       - authorization_code
                       - client_credentials
                       - refresh_token
            options: dict, options depend on the type of request being made, but may include:
                     - scope
                     - authenticating_institution_id
                     - context_institution_id
                     - redirect_uri
                     - code
                     - refresh_token
        """
        self.authorization_server = authorization_server
        if grant_type is None or grant_type not in AccessToken.validGrantTypes:
            raise InvalidGrantType('You must pass a valid grant type to construct an Access Token.')
        self.grant_type = grant_type

        if not options:
            raise NoOptionsPassed('You must pass at least one option to construct an Access Token. Valid options '
                                  'are scope, authenticating_institution_id, context_institution_id, redirect_uri, '
                                  'code and refresh_token')

        if self.grant_type == 'authorization_code' and (
                            'code' not in options or
                            'redirect_uri' not in options or
                            'authenticating_institution_id' not in options or
                            'context_institution_id' not in options):
            raise RequiredOptionsMissing('You must pass the options: code, redirect_uri, '
                                         'authenticating_institution_id and context_institution_id to construct an Access '
                                         'Token using the authorization_code grant type.')

        elif self.grant_type == 'client_credentials' and (
                            not 'scope' in options or
                            not 'authenticating_institution_id' in options or
                            not 'context_institution_id' in options or
                            not 'scope' in options):
            raise RequiredOptionsMissing(
                'You must pass the options: scope, authenticating_institution_id and context_institution_id ' +
                'to construct an Access Token using the client_credential grant type.')

        elif self.grant_type == 'refresh_token' and 'refresh_token' not in options:
            raise RequiredOptionsMissing(
                'You must pass the option refresh_token to construct an Access Token using the ' +
                'refresh_token grant type.')

        if 'scope' in options and not isinstance(options['scope'], list):
            raise RequiredOptionsMissing("scope must be a list of one or more scopes, i.e. ['WMS_NCIP' {, ...}]")

        for key, value in six.iteritems(options):
            if key in AccessToken.valid_options:
                setattr(self, key, value)

        self.access_token_url = self.get_access_token_url()

    def is_expired(self):
        """Test if the token is expired. Returns true if it is."""
        status = False
        if time.mktime(time.strptime(self.expires_at, "%Y-%m-%d %H:%M:%SZ")) < time.time():
            status = True
        return status

    def create(self, wskey, user=None):
        """Create an access token."""
        if not wskey.__class__.__name__ == 'Wskey':
            raise InvalidObject('A valid Wskey object is required.')
        elif user is not None and not user.__class__.__name__ == 'User':
            raise InvalidObject('A valid User object is required.')
        self.wskey = wskey
        if user is not None:
            self.user = user
            self.options = {'user': self.user}
        authorization = self.wskey.get_hmac_signature(
            method='POST',
            request_url=self.access_token_url,
            options=self.options)
        self.request_access_token(authorization, self.access_token_url)

    def refresh(self):
        """Refresh an access token."""
        if self.wskey is None:
            raise InvalidObject('AccessToken must have an associated WSKey Property')

        self.grant_type = 'refresh_token'
        self.access_token_url = self.get_access_token_url()
        authorization = self.wskey.get_hmac_signature(method='POST', request_url=self.access_token_url)
        self.request_access_token(authorization, self.access_token_url)

    def request_access_token(self, authorization, url):
        """ Request an access token. """
        request = six.moves.urllib.request.Request(
            url=url,
            headers={'Authorization': authorization,
         'Accept': 'application/json'},
            data={}
        )

        opener = six.moves.urllib.request.build_opener()

        try:
            result = opener.open(request)
            self.parse_token_response(result.read())
        except six.moves.urllib.error.HTTPError as e:
            self.parse_error_response(e)

    def get_access_token_url(self):
        """ get Access Token URL """
        access_token_url = self.authorization_server + '/accessToken?grant_type=' + self.grant_type
        if self.grant_type == 'refresh_token':
            access_token_url += '&refresh_token=' + self.refresh_token.refresh_token
        elif self.grant_type == 'authorization_code':
            access_token_url += (
                '&' + 'code=' + self.code +
                '&' + 'authenticatingInstitutionId=' + self.authenticating_institution_id +
                '&' + 'contextInstitutionId=' + self.context_institution_id +
                '&' + six.moves.urllib.parse.urlencode({'redirect_uri': self.redirect_uri}))
        elif self.grant_type == 'client_credentials':
            access_token_url += (
                '&authenticatingInstitutionId=' + self.authenticating_institution_id +
                '&contextInstitutionId=' + self.context_institution_id +
                '&scope=' + '%20'.join(self.scope))
        else:
            access_token_url = ''

        return access_token_url

    def parse_token_response(self, response_string):
        """
        Parse the url string which consists of the redirect_uri followed by
        the access token parameters.
        """
        try:
            response_json = json.loads(response_string)
        except ValueError:
            print("ValueError: Unable to decode this Access Token response string to JSON:")
            print(response_string)
            return

        self.access_token_string = response_json.get('access_token', None)
        self.type = response_json.get('token_type', None)
        self.expires_at = response_json.get('expires_at', None)
        self.expires_in = response_json.get('expires_in', None)
        self.context_institution_id = response_json.get('context_institution_id', None)
        self.error_code = response_json.get('error_code', None)

        principal_id = response_json.get('principalID', None)
        principal_idns = response_json.get('principalIDNS', None)

        if principal_id is not None and principal_idns is not None and not principal_id == '' and not principal_idns == '':
            self.user = User(
                authenticating_institution_id=self.authenticating_institution_id,
                principal_id=principal_id,
                principal_idns=principal_idns
            )

        refresh_token = response_json.get('refresh_token', None)

        if refresh_token is not None:
            self.refresh_token = RefreshToken(
                tokenValue=refresh_token,
                expires_in=response_json.get('refresh_token_expires_in', None),
                expires_at=response_json.get('refresh_token_expires_at', None)
            )

    def parse_error_response(self, http_error):
        try:
            error_json = json.loads(http_error.read())
            self.error_code = http_error.getcode()
            self.error_message = error_json['message']
            self.error_detail = error_json['details']
            self.error_url = http_error.geturl()
        except ValueError:
            print("ValueError: Unable to decode this Access Token response string to JSON:")
            print(response_string)
            return

    def __str__(self):

        return string.Template("""
access_token_url: $access_token_url

access_token_string             $access_token_string
authenticating_institution_id:  $authenticating_institution_id
authorization_server:           $authorization_server
code:                           $code
context_institution_id:         $context_institution_id
error_code:                     $error_code
error_message:                  $error_message
error_url:                      $error_url
expires_at:                     $expires_at
expires_in:                     $expires_in
grant_type:                     $grant_type
options:                        $options
redirect_uri:                   $redirect_uri
refresh_token:
$refresh_token
scope:                          $scope
type:                           $type
user:
$user
wskey:
$wskey""").substitute({
            'access_token_url': self.access_token_url.
                replace('?', '?\n' + ' ' * 18).
                replace('&', '\n' + ' ' * 18 + '&'),
            'access_token_string':self.access_token_string,
            'authenticating_institution_id': self.authenticating_institution_id,
            'authorization_server': self.authorization_server,
            'code': self.code,
            'context_institution_id': self.context_institution_id,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'error_url': self.error_url,
            'expires_at': self.expires_at,
            'expires_in': self.expires_in,
            'grant_type': self.grant_type,
            'options': self.options,
            'redirect_uri': self.redirect_uri,
            'refresh_token': self.refresh_token,
            'scope': self.scope,
            'type': self.type,
            'user': self.user,
            'wskey': self.wskey
        })
