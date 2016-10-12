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

import string


class InvalidParameter(Exception):
    """Custom exception - invalid parameter was passed to class"""

    def __init__(self, message):
        self.message = message


class User(object):
    """Class represents a user.

    Class variables:

        principal_id                   string   the principal identifier
        principal_idns                 string   the principal identifier namespace
        authenticating_institution_id  string   the institutionID that the user is authenticating against
    """
    principal_id = None
    principal_idns = None
    authenticating_institution_id = None

    def __init__(self, authenticating_institution_id=None, principal_id=None, principal_idns=None):
        """Constructor.

        Args:
            authenticating_institution_id: string, the institutionID that the user is authenticating against
            principal_id: string, the principal identifier
            principal_idns: string, the principal identifier namespace
        """
        if not authenticating_institution_id:
            raise InvalidParameter('You must set a valid Authenticating Institution ID')
        if not principal_id:
            raise InvalidParameter('You must set a valid principal_id')
        if not principal_idns:
            raise InvalidParameter('You must set a valid principal_idns')

        self.authenticating_institution_id = authenticating_institution_id
        self.principal_id = principal_id
        self.principal_idns = principal_idns

    def __str__(self):

        return string.Template("""principal_id:                  $principal_id
principal_idns:                $principal_idns
authenticating_institution_id: $authenticating_institution_id
""").substitute({
            'principal_id': self.principal_id,
            'principal_idns': self.principal_idns,
            'authenticating_institution_id': self.authenticating_institution_id,
        })
