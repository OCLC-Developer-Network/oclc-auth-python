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

__author__ = 'campbelg@oclc.org (George Campbell)'

from urlparse import urlparse
import urllib
from authcode import AuthCode
from accesstoken import AccessToken
import time
import math
import random
import hmac
import hashlib
import base64
import collections
import copy


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
    validOptions     dict     list of valid options that can be passed to this class
    key              string   the clientID (public) portion of the WSKey
    secret           string   the secret (private) portion of the WSKey
    redirectUri      string   the url of the web app, for example https://localhost:8000/auth/
    services         list     the web services associated with the WSKey, for example ['WorldCatMetadataAPI']
    debugTimeStamp   string   if not None, then overrides the calculated timestamp. Used for unit tests.
    debugNonce       string   if not None, then overrides the calculated nonce. Used for unit tests.
    bodyHash         string   set to None - current implementation of OCLC's OAuth2 does not use body hashing
    authParams       dict     custom list of authentication parameters - used for some specialized APIs
    user             object   a user object associated with the key. See user.py in the authliboclc library folder.
    """

    validOptions = ['redirectUri', 'services']
    key = None
    secret = None
    redirectUri = None
    services = None
    debugTimestamp = None
    debugNonce = None
    bodyHash = None
    authParams = None
    user = None

    def __init__(self, key, secret, options=None):
        """Constructor.

        Args:
          key: string, the clientID (public) portion of the WSKey
          secret: string, the secret (private) portion of the WSKey
          options: dict
                   - redirectUri: string, the url that the client authenticates from
                                  ie, https://localhost:8000/auth/
                   - services: list, the services associated with the key
                               ie, ['WMS_ACQ','WorldCatMetadataAPI']
                               * note that including 'refresh_token' as a service causes access token requests
                                 to return a refresh token with the access token.
        """
        if key == None or secret == None:
            raise InvalidObject('A valid key and secret are required to construct a WSKey.')
        elif options == '':
            raise InvalidObject('Options must be sent as a dictionary object.')

        self.key = key
        self.secret = secret

        """If options are included, they must include a redirectUri and one or more services."""
        if options != None and len(options) > 0:
            if not 'redirectUri' in options:
                raise InvalidParameter('Missing redirectUri option.')
            elif options['redirectUri'] == None:
                raise InvalidParameter('redirectUri must contain a value.')
            else:
                scheme = urlparse(options['redirectUri']).scheme
                if scheme != 'http' and scheme != 'https':
                    raise InvalidParameter('Invalid redirectUri. Must begin with http:// or https://')

            if not 'services' in options:
                raise InvalidParameter('Missing service option.')
            elif options['services'] == None or len(options['services']) == 0:
                raise InvalidParameter('A list containing at least one service is required.')

            for key, value in options.items():
                if key in Wskey.validOptions:
                    setattr(self, key, value)


    def getLoginUrl(self, authenticatingInstitutionId=None, contextInstitutionId=None):
        """Creates a login url.

        Args:
            authenticatingInstitutionId: string, the institution which the user authenticates against
            contextInstitutionId: string, the institution which the user will make requests against

        Returns:
            string, the login URL to be used to authenticate the user
        """
        if authenticatingInstitutionId == None:
            raise InvalidParameter('You must pass an authenticating institution ID')
        if contextInstitutionId == None:
            raise InvalidParameter('You must pass a context institution ID')

        authCode = AuthCode(**{
            'clientId': self.key,
            'authenticatingInstitutionId': authenticatingInstitutionId,
            'contextInstitutionId': contextInstitutionId,
            'redirectUri': self.redirectUri,
            'scopes': self.services
        })

        return authCode.getLoginUrl()

    def getAccessTokenWithAuthCode(self, code=None, authenticatingInstitutionId=None, contextInstitutionId=None):
        """Retrieves an Access Token using an Authentication Code

        Args:
            code: string, the authentication code returned after the user authenticates
            authenticatingInstitutionId: string, the institution the user authenticates against
            contextInstitutionId: string, the institution that the requests will be made against

        Returns:
            object, an access token
        """

        if code == None or code == '':
            raise InvalidParameter('You must pass a code')
        if authenticatingInstitutionId == None or authenticatingInstitutionId == '':
            raise InvalidParameter('You must pass an authenticatingInstitutionId')
        if contextInstitutionId == None or contextInstitutionId == '':
            raise InvalidParameter('You must pass a contextInstitutionId')

        accessToken = AccessToken(**{
            'grantType': 'authorization_code',
            'options': {
                'code': code,
                'authenticatingInstitutionId': authenticatingInstitutionId,
                'contextInstitutionId': contextInstitutionId,
                'redirectUri': self.redirectUri
            }
        })

        accessToken.create(**{
            'wskey': self,
            'user': None
        })

        return accessToken

    def getAccessTokenWithClientCredentials(self, authenticatingInstitutionId=None, contextInstitutionId=None,
                                            user=None):
        """Retrieves an Access Token using a Client Credentials Grant

        Args:
            authenticatingInstitutionId: string, the institution the user authenticates against
            contextInstitutionId: string, the institution that the requests will be made against
            user: object, a user object

        Returns:
            object, an access token
        """

        if authenticatingInstitutionId == None or authenticatingInstitutionId == '':
            raise InvalidParameter('You must pass an authenticating_institution_id')
        if contextInstitutionId == None or contextInstitutionId == '':
            raise InvalidParameter('You must pass a context_institution_id')
        if self.services == None or self.services == [] or len(self.services) == 0 or self.services == ['']:
            raise InvalidParameter('You must set at least on service on the Wskey')

        accessToken = AccessToken(**{
            'grantType': 'client_credentials',
            'options': {
                'authenticatingInstitutionId': authenticatingInstitutionId,
                'contextInstitutionId': contextInstitutionId,
                'scope': self.services
            }
        })

        accessToken.create(**{
            'wskey': self,
            'user': user
        })

        return accessToken

    def getHMACSignature(self, method=None, requestUrl=None, options=None):
        """Signs a url with an HMAC signature and builds an Authorization header

        Args:
            method: string, GET, POST, PUT, DELETE, etc.
            requestUrl: string, the url to be signed
            options: dict
                     - user: object, a user object
                     - authparams: dict, various key value pairs to be added to the authorization header. For example,
                                   userid and password. Depends on the API and its specialized needs.

        Returns:
            authorizationHeader: string, the Authorization header to be added to the request.
        """

        if self.secret == None or self.secret == '':
            raise InvalidParameter('You must construct a WSKey with a secret to build an HMAC Signature.')
        if method == None or method == '':
            raise InvalidParameter('You must pass an HTTP Method to build an HMAC Signature.')
        if requestUrl == None or requestUrl == '':
            raise InvalidParameter('You must pass a valid request URL to build an HMAC Signature.')

        if options != None:
            for key, value in options.items():
                setattr(self, key, value)

        timestamp = self.debugTimestamp
        if timestamp == None or timestamp == '':
            timestamp = str(int(time.time()))

        nonce = self.debugNonce
        if nonce == None or nonce == '':
            nonce = str(hex(int(math.floor(random.random() * 4026531839 + 268435456))))

        signature = self.signRequest(**{
            'method': method,
            'requestUrl': requestUrl,
            'timestamp': timestamp,
            'nonce': nonce})

        q = '"'
        qc = '",'

        authorizationHeader = ("http://www.worldcat.org/wskey/v2/hmac/v1 " +
                               "clientId=" + q + self.key + qc +
                               "timestamp=" + q + timestamp + qc +
                               "nonce=" + q + nonce + qc +
                               "signature=" + q + signature)

        if self.user != None or self.authParams != None:
            authorizationHeader += (qc + self.AddAuthParams(self.user, self.authParams))
        else:
            authorizationHeader += q

        return authorizationHeader


    def signRequest(self, method, requestUrl, timestamp, nonce):
        """Requests a normalized request and hashes it

        Args:
            method: string, GET, POST, etc.
            requestUrl: string, the URL to be hashed
            timestamp: string, POSIX time
            nonce: string, a random 32 bit integer expressed in hexadecimal format

        Returns:
            A base 64 encoded SHA 256 HMAC hash
        """
        normalizedRequest = self.normalizeRequest(**{
            'method': method,
            'requestUrl': requestUrl,
            'timestamp': timestamp,
            'nonce': nonce
        })

        digest = hmac.new(self.secret, msg=normalizedRequest, digestmod=hashlib.sha256).digest()
        return str(base64.b64encode(digest).decode())


    def normalizeRequest(self, method, requestUrl, timestamp, nonce):
        """Prepares a normalized request for hashing

         Args:
            method: string, GET, POST, etc.
            requestUrl: string, the URL to be hashed
            timestamp: string, POSIX time
            nonce: string, a random 32 bit integer expressed in hexadecimal format

        Returns:
            normalizedRequest: string, the normalized request to be hashed
        """
        signatureUrl = 'https://www.oclc.org/wskey'
        parsedSignatureUrl = urlparse(urllib.unquote(signatureUrl).decode('utf-8'))
        parsedRequestUrl = urlparse(urllib.unquote(requestUrl).decode('utf-8'))

        host = str(parsedSignatureUrl.netloc)

        if parsedSignatureUrl.port != None:
            port = str(parsedSignatureUrl.port)
        else:
            if str(parsedSignatureUrl.scheme) == 'http':
                port = '80'
            elif str(parsedSignatureUrl.scheme) == 'https':
                port = '443'

        path = str(parsedSignatureUrl.path)

        """ OCLC's OAuth implementation does not currently use body hashing, so this should always be ''."""
        bodyHash = ''
        if self.bodyHash != None:
            bodyHash = self.bodyHash

        """The base normalized request."""
        normalizedRequest = (self.key + '\n' +
                             timestamp + '\n' +
                             nonce + '\n' +
                             bodyHash + '\n' +
                             method + '\n' +
                             host + '\n' +
                             port + '\n' +
                             path + '\n')

        """Add the request parameters to the normalized request."""
        parameters = {}
        if parsedRequestUrl.query != None:
            for param in parsedRequestUrl.query.split('&'):
                key = (param.split('='))[0]
                value = (param.split('='))[1]
                parameters[key] = value

        """URL encode normalized request per OAuth 2 Official Specification."""
        for key in collections.OrderedDict(sorted(parameters.items())):
            nameAndValue = urllib.urlencode({key: parameters[key]})
            nameAndValue = nameAndValue.replace('+', '%20')
            nameAndValue = nameAndValue.replace('*', '%2A')
            nameAndValue = nameAndValue.replace('%7E', '~')
            normalizedRequest += nameAndValue + '\n'

        return normalizedRequest


    def AddAuthParams(self, user, authParams):
        """Adds users custom authentication parameters, if any, to the Normalized request

        Args:
            user: object, a user object
            authParams: dict, a list of parameters to add the custom parameters to

        Returns:
            authValuePairs: dict, the authParams with any custom parameters added to them
        """
        authValuePairs = ''
        combinedParams = copy.copy(authParams)

        if combinedParams == None or combinedParams == '':
            combinedParams = {}

        if user != None:
            combinedParams['principalID'] = user.principalID
            combinedParams['principalIDNS'] = user.principalIDNS

        counter = 0

        for key in collections.OrderedDict(sorted(combinedParams.items())):

            authValuePairs += key + '=' + '"' + combinedParams[key]
            counter += 1
            if counter == len(combinedParams):
                authValuePairs += '"'
            else:
                authValuePairs += '",'

        return authValuePairs
