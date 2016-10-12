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

"""
Class represents and authentication code object

HMAC Requests, which are strictly server side, use an Authenication Code object to store their parameters
and perform hashing.
"""

import string

import six


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
        authorization_server          string   the oclc server that conducts authentication
        client_id                     string   the public portion of the Web Services Key (WSKey)
        authenticating_institution_id string   the institutionID that is authenticated against
        context_institution_id        string   the institutionID that the request is made against
        redirect_uri                  string   the redirect_uri for the request
        scopes                        list     a list of one or more web services
    """
    authorization_server = None
    client_id = None
    authenticating_institution_id = None
    context_institution_id = None
    redirect_uri = None
    scopes = None

    def __init__(self,
                 authorization_server,
                 client_id=None,
                 authenticating_institution_id=None,
                 context_institution_id=None,
                 redirect_uri=None,
                 scopes=None):
        """Constructor.

        Args:
            authorization_server: string, url of the authorization server
            client_id: string, the public portion of the Web Services Key (WSKey)
            authenticating_institution_id: string, the institutionID that is authenticated against
            context_institution_id: string, the institutionID that the request is made against
            redirect_uri: string, the redirect_uri for the request
            scopes: list, a list of one or more web services
        """

        self.authorization_server = authorization_server
        self.client_id = client_id
        self.authenticating_institution_id = authenticating_institution_id
        self.context_institution_id = context_institution_id
        self.redirect_uri = redirect_uri
        self.scopes = scopes

        if self.client_id is None:
            raise InvalidParameter('Required option missing: client_id.')
        elif self.client_id == '':
            raise InvalidParameter('Cannot be empty string: client_id.')

        if self.authenticating_institution_id is None:
            raise InvalidParameter('Required option missing: authenticating_institution_id.')
        elif self.authenticating_institution_id == '':
            raise InvalidParameter('Cannot be empty string: authenticating_institution_id.')

        if self.context_institution_id is None:
            raise InvalidParameter('Required option missing: context_institution_id.')
        elif self.context_institution_id == '':
            raise InvalidParameter('Cannot be empty string: context_institution_id.')

        if self.redirect_uri is None:
            raise InvalidParameter('Required option missing: redirect_uri.')
        elif self.redirect_uri == '':
            raise InvalidParameter('Cannot be empty string: redirect_uri.')
        else:
            scheme = six.moves.urllib.parse.urlparse("".join(self.redirect_uri)).scheme
            if not scheme == 'http' and not scheme == 'https':
                raise InvalidParameter('Invalid redirect_uri. Must begin with http:// or https://')

        if self.scopes is None or self.scopes == '':
            raise InvalidParameter(
                'Required option missing: scopes. Note scopes must be a list of one or more scopes.')
        elif not self.scopes or not self.scopes[0]:
            raise InvalidParameter('You must pass at least one valid scope')

    def get_login_url(self):
        """Returns a login url based on the auth code parameters."""
        return (
            self.authorization_server + '/authorizeCode' +
            '?' + 'authenticatingInstitutionId=' + self.authenticating_institution_id +
            '&' + 'client_id=' + self.client_id +
            '&' + 'contextInstitutionId=' + self.context_institution_id +
            '&' + six.moves.urllib.parse.urlencode({'redirect_uri': self.redirect_uri}) +
            '&' + 'response_type=code' +
            '&' + 'scope=' + " ".join(self.scopes)
        )

    def __str__(self):

        return string.Template("""authorization_server:          $authorization_server
client_id:                     $client_id
authenticating_institution_id: $authenticating_institution_id
context_institution_id:        $context_institution_id
redirect_uri:                  $redirect_uri
scopes:                        $scopes
""").substitute({
            'authorization_server': self.authorization_server,
            'client_id': self.client_id,
            'authenticating_institution_id': self.authenticating_institution_id,
            'context_institution_id': self.context_institution_id,
            'redirect_uri': self.redirect_uri,
            'scopes': self.scopes}
        )

