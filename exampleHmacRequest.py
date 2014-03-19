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

from authliboclc import wskey
from authliboclc import user
import urllib2

#
# You must supply these parameters to authenticate
# Note - a WSKey consists of two parts, a public clientID and a private secret
#

key = '{clientID}'
secret = '{secret}'
principalID = '{principalID}'
principalIDNS = '{principalIDNS}'
authenticatingInstitutionID = '{institutionID}'  # 128807 = Sandbox Institution

requestUrl = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN'

myWskey = wskey.Wskey(**{
    'key': key,
    'secret': secret,
    'options': None})

myUser = user.User(**{
    'authenticatingInstitutionID': authenticatingInstitutionID,
    'principalID': principalID,
    'principalIDNS': principalIDNS
})

authorizationHeader = myWskey.getHMACSignature(**{
    'method': 'GET',
    'requestUrl': requestUrl,
    'options': {
        'user': myUser,
        'authParams': None}
})

myRequest = urllib2.Request(**{
    'url': requestUrl,
    'data': None,
    'headers': {'Authorization': authorizationHeader}
})

try:
    xmlresult = urllib2.urlopen(myRequest).read()
    print(xmlresult)

except urllib2.HTTPError, e:
    print ('** ' + str(e) + ' **')
    if key == '{clientID}':
        print('You need to supply valid parameters - see line 28.')
