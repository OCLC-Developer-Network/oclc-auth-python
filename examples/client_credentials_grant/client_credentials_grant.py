#!/usr/bin/env python
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

# Example of retrieving a token with Client Credentials Grant

from authliboclc import wskey

#
# Authentication Parameters
#

key = '{clientID}'
secret = '{secret}'
authenticating_institution_id = '{institutionID}'
context_institution_id = '{institutionID}'

my_wskey = wskey.Wskey(
    key=key,
    secret=secret,
    options={'services': ['WorldCatDiscoveryAPI']})

access_token = my_wskey.get_access_token_with_client_credentials(authenticating_institution_id, context_institution_id)

print("")
if (access_token.access_token_string == None):
    print("error_code:    " + `access_token.error_code`);
    print("error_message: " + access_token.error_message);
    print("error_url:     " + access_token.error_url);
else:
    print("access token:  " + access_token.access_token_string)
    print("expires_in:    " + `access_token.expires_in`)
    print("expires_at:    " + access_token.expires_at)
    print("type:          " + access_token.type)
    if (access_token.refresh_token != None):
        print("refresh_token: " + access_token.refresh_token)
print("")