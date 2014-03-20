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

from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse
from authliboclc import wskey
import urllib2
import pickle

"""Django view generator"""


def index(request):
    """You must fill in the clientID and secret with your WSKey parameters"""
    key = '{clientID}'
    secret = '{secret}'

    """We use the Worldcat Metadata API to test the Access Token"""
    services = ['WorldCatMetadataAPI', 'refresh_token']

    """The response object is where we write data to display on the page."""
    response = HttpResponse()

    response.write("""<!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://static1.worldcat.org/yui/combo?pure/0.4.2/pure-min.css">
        <style>
            body {width:800px; margin:auto}
            h1 {font-size: 150%}
            td {vertical-align:top}
            .error {line-height: 140%; background-color: lightcoral; padding: 3px 20px; border-radius: 12px}
            pre {font-size: 83%; margin-top:0}
        </style>
    </head>
    <body>
        <h1>Authentication Token & Bibliographic Record - Django Example</h1>
    """)

    """The redirect URI is calculated here and must match the redirect URI assigned to your WSKey"""
    if request.is_secure:
        """You must use SSL to request an Access token"""
        redirectUri = 'https://' + request.get_host() + request.path  # https://localhost:8000/auth/
    else:
        """This won't work."""
        redirectUri = 'http://' + request.get_host() + request.path  # http://localhost:8000/auth/

    """Populate the WSKey object its parameters"""
    myWskey = wskey.Wskey(**{
        'key': key,
        'secret': secret,
        'options': {
            'services': services,
            'redirectUri': redirectUri
        }
    })

    accessToken = None

    """If an accessToken is stored in the current session load it."""
    if request.session.get('accessToken', None) != None:
        accessToken = pickle.loads(request.session.get('accessToken', None))

    """If the accessToken we loaded is expired, we can't use it."""
    if accessToken != None and accessToken.isExpired():
        accessToken = None

    """If there is a code parameter on the current URL, load it."""
    code = request.GET.get('code', None)

    """If there are error parameters on the current URL, load them."""
    error = request.GET.get('error', None)
    errorDescription = request.GET.get('error_description', None)

    if error != None:
        """If an error was returned, display it."""
        response.write('<p class="error">Error: ' + error + '<br>' + errorDescription + '</p>')

    elif accessToken == None and code == None:
        """Initiate user authentication by executing a redirect to the IDM sign in page."""
        loginUrl = myWskey.getLoginUrl(**{
            'authenticatingInstitutionId': '128807',
            'contextInstitutionId': '128807'
        })
        response['Location'] = loginUrl
        response.status_code = '303'

    elif accessToken == None and code != None:
        """Request an access token using the user authentication code returned after the user authenticated"""
        """Then request a bibliographic record"""
        accessToken = myWskey.getAccessTokenWithAuthCode(**{
            'code': code,
            'authenticatingInstitutionId': '128807',
            'contextInstitutionId': '128807'
        })

        if accessToken.errorCode == None:
            request.session['accessToken'] = pickle.dumps(accessToken)
            response.write('<p><strong>Access Token</strong> NOT FOUND in this session, so I requested a new one.</p>')

        response.write(formatAccessToken(**{
            'accessToken': accessToken
        }))

        if accessToken.errorCode == None:
            response.write(getBibRecord(**{
                'accessToken': accessToken,
                'wskey': myWskey
            }))

    elif accessToken != None:
        """We already have an Access Token, so display the token and request a Bibliographic Record"""
        if accessToken.errorCode == None:
            response.write('<p><strong>Access Token</strong> found in this session, and it is still valid.</p>')

        response.write(formatAccessToken(**{
            'accessToken': accessToken
        }))

        if accessToken.errorCode == None:
            response.write(getBibRecord(**{
                'accessToken': accessToken,
                'wskey': myWskey
            }))

    return response


"""Display all the parameters of the Access Token"""


def formatAccessToken(accessToken):
    ret = '<h2>Access Token</h2>'

    ret += '<table class="pure-table">'

    if accessToken.errorCode != None:
        ret += '<tr><td>Error Code</td><td>' + str(accessToken.errorCode) + '</td></tr>'
        ret += '<tr><td>Error Message</td><td>' + str(accessToken.errorMessage) + '</td></tr>'
        ret += ('<tr><td>Error Url</td><td><pre>' +
                str(accessToken.errorUrl).replace('?', '?\n').replace('&', '\n&') + '</pre></td></tr>')

    else:
        ret += '<tr><td>access_token</td><td>' + str(accessToken.accessTokenString) + '</td></tr>'
        ret += '<tr><td>token_type</td><td>' + str(accessToken.type) + '</td></tr>'
        ret += '<tr><td>expires_at</td><td>' + str(accessToken.expiresAt) + '</td></tr>'
        ret += '<tr><td>expires_in</td><td>' + str(accessToken.expiresIn) + '</td></tr>'

        if accessToken.user != None:
            ret += '<tr><td>principalIDNS</td><td>' + str(accessToken.user.principalID) + '</td></tr>'
            ret += '<tr><td>principalID</td><td>' + str(accessToken.user.principalIDNS) + '</td></tr>'
            ret += '<tr><td>context_institution_id</td><td>' + str(accessToken.contextInstitutionId) + '</td></tr>'

        if accessToken.refreshToken != None:
            ret += '<tr><td>refresh_token</td><td>' + str(accessToken.refreshToken.refreshToken) + '</td></tr>'
            ret += '<tr><td>refresh_token_expires_at</td><td>' + str(accessToken.refreshToken.expiresAt) + '</td></tr>'
            ret += '<tr><td>refresh_token_expires_in</td><td>' + str(accessToken.refreshToken.expiresIn) + '</td></tr>'

    ret += '</table>'
    return ret


"""Use an Access Token's User Parameter to request a Bibliographic Record"""


def getBibRecord(accessToken, wskey):
    requestUrl = (
        'https://worldcat.org/bib/data/823520553?' +
        'classificationScheme=LibraryOfCongress' +
        '&holdingLibraryCode=MAIN'
    )

    authorizationHeader = wskey.getHMACSignature(**{
        'method': 'GET',
        'requestUrl': requestUrl,
        'options': {
            'user': accessToken.user
        }
    })

    myRequest = urllib2.Request(**{
        'url': requestUrl,
        'data': None,
        'headers': {'Authorization': authorizationHeader}
    })

    try:
        xmlResult = urllib2.urlopen(myRequest).read()

    except urllib2.HTTPError, e:
        xmlResult = str(e)

    ret = '<h2>Bibliographic Record</h2>'
    ret += '<pre>' + xmlResult.replace('<', '&lt;') + '</pre>'

    return ret