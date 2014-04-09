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

# Sample HMAC Hashing for Bibliographic record retrieval

from authliboclc import wskey, user
import urllib2

#
# You must supply these parameters to authenticate
# Note - a WSKey consists of two parts, a public clientID and a private secret
#

key = '{clientID}'
secret = '{secret}'
principal_id = '{principalID}'
principal_idns = '{principalIDNS}'
authenticating_institution_id = '{institutionID}'

request_url = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN'

my_wskey = wskey.Wskey(
    key=key,
    secret=secret,
    options=None)

my_user = user.User(
    authenticating_institution_id=authenticating_institution_id,
    principal_id=principal_id,
    principal_idns=principal_idns
)

authorization_header = my_wskey.get_hmac_signature(
    method='GET',
    request_url=request_url,
    options={
        'user': my_user,
        'auth_params': None}
)

print(authorization_header)

my_request = urllib2.Request(
    url=request_url,
    data=None,
    headers={'Authorization': authorization_header}
)

try:
    xml_result = urllib2.urlopen(my_request).read()
    print(xml_result)

except urllib2.HTTPError, e:
    print ('** ' + str(e) + ' **')
    if key == '{clientID}':
        print('You need to supply valid parameters - see line 30.')
