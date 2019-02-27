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

"""Class that represents a Web Services Key (WSKey)

Stores the WSKey parameters and methods for HMAC Hashing and requesting access tokens.

"""

import copy, base64, hashlib, hmac, math, random, string, time

from .authcode import AuthCode
from .accesstoken import AccessToken

import six

AUTHORIZATION_SERVER = 'https://authn.sd00.worldcat.org/oauth2'
SIGNATURE_URL = 'https://www.oclc.org/wskey'


class InvalidObject(Exception):
    """Custom exception - invalid object was passed to class"""

    def __init__(self, message):
        self.message = message


class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""

    def __init__(self, message):
        self.message = message


class Wskey(object):
    """Web Services Key object

    Class variables
    authorization_server string   url of the authorization server
    valid_options        dict     list of valid options that can be passed to this class
    key                  string   the clientID (public) portion of the WSKey
    secret               string   the secret (private) portion of the WSKey
    redirect_uri         string   the url of the web app, for example https://localhost:8000/auth/
    services             list     the web services associated with the WSKey, for example ['WorldCatMetadataAPI']
    debug_time_stamp     string   if not None, then overrides the calculated timestamp. Used for unit tests.
    debug_nonce          string   if not None, then overrides the calculated nonce. Used for unit tests.
    body_hash            string   set to None - current implementation of OCLC's OAuth2 does not use body hashing
    auth_params          dict     custom list of authentication parameters - used for some specialized APIs
    user                 object   a user object associated with the key. See user.py in the authliboclc library folder.
    """

    authorization_server = AUTHORIZATION_SERVER
    valid_options = ['redirect_uri', 'services']
    key = None
    secret = None
    redirect_uri = None
    services = None
    debug_time_stamp = None
    debug_nonce = None
    body_hash = None
    auth_params = None
    user = None

    def __init__(self, key, secret, options=None):
        """Constructor.

        Args:
          key: string, the clientID (public) portion of the WSKey
          secret: string, the secret (private) portion of the WSKey
          options: dict
                   - redirect_uri: string, the url that the client authenticates from
                                  ie, https://localhost:8000/auth/
                   - services: list, the services associated with the key
                               ie, ['WMS_ACQ','WorldCatMetadataAPI']
                               * note that including 'refresh_token' as a service causes access token requests
                                 to return a refresh token with the access token.
        """
        if key is None or secret is None:
            raise InvalidObject('A valid key and secret are required to construct a WSKey.')
        elif options == '':
            raise InvalidObject('Options must be sent as a dictionary object.')

        self.key = key
        self.secret = secret

        """If options are included, they must include a redirect_uri and one or more services."""
        if options:
            if 'redirect_uri' in options:
                if options['redirect_uri'] is None:
                    raise InvalidParameter('redirect_uri must contain a value.')
                else:
                    scheme = six.moves.urllib.parse.urlparse(options['redirect_uri']).scheme
                    if not scheme == 'http' and not scheme == 'https':
                        raise InvalidParameter('Invalid redirect_uri. Must begin with http:// or https://')

            if 'services' not in options:
                raise InvalidParameter('Missing service option.')
            elif not options['services']:
                raise InvalidParameter('A list containing at least one service is required.')

            for key, value in six.iteritems(options):
                if key in Wskey.valid_options:
                    setattr(self, key, value)

    def get_login_url(self, authenticating_institution_id=None, context_institution_id=None):
        """Creates a login url.

        Args:
            authenticating_institution_id: string, the institution which the user authenticates against
            context_institution_id: string, the institution which the user will make requests against

        Returns:
            string, the login URL to be used to authenticate the user
        """
        if authenticating_institution_id is None:
            raise InvalidParameter('You must pass an authenticating institution ID')
        if context_institution_id is None:
            raise InvalidParameter('You must pass a context institution ID')

        authCode = AuthCode(
            authorization_server=self.authorization_server,
            client_id=self.key,
            authenticating_institution_id=authenticating_institution_id,
            context_institution_id=context_institution_id,
            redirect_uri=self.redirect_uri,
            scopes=self.services
        )

        return authCode.get_login_url()

    def get_access_token_with_auth_code(self, code=None, authenticating_institution_id=None,
                                        context_institution_id=None):
        """Retrieves an Access Token using an Authentication Code

        Args:
            code: string, the authentication code returned after the user authenticates
            authenticating_institution_id: string, the institution the user authenticates against
            context_institution_id: string, the institution that the requests will be made against

        Returns:
            object, an access token
        """

        if not code:
            raise InvalidParameter('You must pass a code')
        if not authenticating_institution_id:
            raise InvalidParameter('You must pass an authenticating_institution_id')
        if not context_institution_id:
            raise InvalidParameter('You must pass a context_institution_id')

        accessToken = AccessToken(
            authorization_server=self.authorization_server,
            grant_type='authorization_code',
            options={
                'code': code,
                'authenticating_institution_id': authenticating_institution_id,
                'context_institution_id': context_institution_id,
                'redirect_uri': self.redirect_uri
            }
        )

        accessToken.create(wskey=self, user=None)

        return accessToken

    def get_access_token_with_client_credentials(self, authenticating_institution_id=None, context_institution_id=None, user=None):
        """Retrieves an Access Token using a Client Credentials Grant

        Args:
            authenticating_institution_id: string, the institution the user authenticates against
            context_institution_id: string, the institution that the requests will be made against
            user: object, a user object associated with the key. See user.py in the authliboclc library folder.

        Returns:
            object, an access token
        """

        if not authenticating_institution_id:
            raise InvalidParameter('You must pass an authenticating_institution_id')
        if not context_institution_id:
            raise InvalidParameter('You must pass a context_institution_id')
        if not self.services or self.services == ['']:
            raise InvalidParameter('You must set at least one service on the Wskey')

        accessToken = AccessToken(
            authorization_server=self.authorization_server,
            grant_type='client_credentials',
            options={
                'authenticating_institution_id': authenticating_institution_id,
                'context_institution_id': context_institution_id,
                'scope': self.services
            }
        )

        accessToken.create(wskey=self, user=user)

        return accessToken

    def get_hmac_signature(self, method=None, request_url=None, options=None):
        """Signs a url with an HMAC signature and builds an Authorization header

        Args:
            method: string, GET, POST, PUT, DELETE, etc.
            request_url: string, the url to be signed
            options: dict
                     - user: object, a user object
                     - auth_params: dict, various key value pairs to be added to the authorization header. For example,
                                   userid and password. Depends on the API and its specialized needs.

        Returns:
            authorization_header: string, the Authorization header to be added to the request.
        """

        if not self.secret:
            raise InvalidParameter('You must construct a WSKey with a secret to build an HMAC Signature.')
        if not method:
            raise InvalidParameter('You must pass an HTTP Method to build an HMAC Signature.')
        if not request_url:
            raise InvalidParameter('You must pass a valid request URL to build an HMAC Signature.')

        if options is not None:
            for key, value in six.iteritems(options):
                setattr(self, key, value)

        timestamp = self.debug_time_stamp
        if not timestamp:
            timestamp = str(int(time.time()))

        nonce = self.debug_nonce
        if not nonce:
            nonce = str(hex(int(math.floor(random.random() * 4026531839 + 268435456))))

        signature = self.sign_request(
            method=method,
            request_url=request_url,
            timestamp=timestamp,
            nonce=nonce
        )

        q = '"'
        qc = '",'

        authorization_header = ("http://www.worldcat.org/wskey/v2/hmac/v1 " +
                                "clientID=" + q + self.key + qc +
                                "timestamp=" + q + timestamp + qc +
                                "nonce=" + q + nonce + qc +
                                "signature=" + q + signature)

        if self.user is not None or self.auth_params is not None:
            authorization_header += (qc + self.add_auth_params(self.user, self.auth_params))
        else:
            authorization_header += q

        return authorization_header

    def sign_request(self, method, request_url, timestamp, nonce):
        """Requests a normalized request and hashes it

        Args:
            method: string, GET, POST, etc.
            request_url: string, the URL to be hashed
            timestamp: string, POSIX time
            nonce: string, a random 32 bit integer expressed in hexadecimal format

        Returns:
            A base 64 encoded SHA 256 HMAC hash
        """
        normalized_request = self.normalize_request(
            method=method,
            request_url=request_url,
            timestamp=timestamp,
            nonce=nonce
        )

        digest = hmac.new(self.secret.encode('utf-8'),
                          msg=normalized_request.encode('utf-8'),
                          digestmod=hashlib.sha256).digest()
        return str(base64.b64encode(digest).decode())

    def normalize_request(self, method, request_url, timestamp, nonce):
        """Prepares a normalized request for hashing

         Args:
            method: string, GET, POST, etc.
            request_url: string, the URL to be hashed
            timestamp: string, POSIX time
            nonce: string, a random 32 bit integer expressed in hexadecimal format

        Returns:
            normalized_request: string, the normalized request to be hashed
        """
        signature_url = SIGNATURE_URL
        parsed_signature_url = six.moves.urllib.parse.urlparse(six.moves.urllib.parse.unquote(signature_url))
        parsed_request_url = six.moves.urllib.parse.urlparse(six.moves.urllib.parse.unquote(request_url))

        host = str(parsed_signature_url.netloc)

        if parsed_signature_url.port is not None:
            port = str(parsed_signature_url.port)
        else:
            if str(parsed_signature_url.scheme) == 'http':
                port = '80'
            elif str(parsed_signature_url.scheme) == 'https':
                port = '443'

        path = str(parsed_signature_url.path)

        """ OCLC's OAuth implementation does not currently use body hashing, so this should always be ''."""
        body_hash = ''
        if self.body_hash is not None:
            body_hash = self.body_hash

        """The base normalized request."""
        normalized_request = (self.key + '\n' +
                              timestamp + '\n' +
                              nonce + '\n' +
                              body_hash + '\n' +
                              method + '\n' +
                              host + '\n' +
                              port + '\n' +
                              path + '\n')

        """Add the request parameters to the normalized request."""
        parameters = {}
        if parsed_request_url.query:
            for param in parsed_request_url.query.split('&'):
                key = (param.split('='))[0]
                value = (param.split('='))[1]
                parameters[key] = value

        """URL encode normalized request per OAuth 2 Official Specification."""
        for key in sorted(parameters):
            nameAndValue = six.moves.urllib.parse.urlencode({key: parameters[key]})
            nameAndValue = nameAndValue.replace('+', '%20')
            nameAndValue = nameAndValue.replace('*', '%2A')
            nameAndValue = nameAndValue.replace('%7E', '~')
            normalized_request += nameAndValue + '\n'

        return normalized_request

    def add_auth_params(self, user, auth_params):
        """Adds users custom authentication parameters, if any, to the Normalized request

        Args:
            user: object, a user object
            auth_params: dict, a list of parameters to add the custom parameters to

        Returns:
            authValuePairs: dict, the auth_params with any custom parameters added to them
        """
        authValuePairs = ''
        combinedParams = copy.copy(auth_params)

        if not combinedParams:
            combinedParams = {}

        if user is not None:
            combinedParams['principalID'] = user.principal_id
            combinedParams['principalIDNS'] = user.principal_idns

        counter = 0

        for key in sorted(combinedParams):

            authValuePairs += key + '=' + '"' + combinedParams[key]
            counter += 1
            if counter == len(combinedParams):
                authValuePairs += '"'
            else:
                authValuePairs += '",'

        return authValuePairs

    def __str__(self):

        return string.Template("""key:              $key
secret:           $secret
redirect_uri:     $redirect_uri
services:         $services
debug_time_stamp: $debug_time_stamp
debug_nonce:      $debug_nonce
body_hash:        $body_hash
auth_params:      $auth_params
user:
$user""").substitute({
            'key': self.key,
            'secret': self.secret,
            'redirect_uri': self.redirect_uri,
            'services': self.services,
            'debug_time_stamp': self.debug_time_stamp,
            'debug_nonce': self.debug_nonce,
            'body_hash': self.body_hash,
            'auth_params': self.auth_params,
            'user': self.user
        })
