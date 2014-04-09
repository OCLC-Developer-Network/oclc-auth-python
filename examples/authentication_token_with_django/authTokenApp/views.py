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

    """Default values for the Sandbox Institution. You may want to change them to your institution's values"""
    authenticating_institution_id = '128807'
    context_institution_id = '128807'

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
        redirect_uri = 'https://' + request.get_host() + request.path  # https://localhost:8000/auth/
    else:
        """This won't work."""
        redirect_uri = 'http://' + request.get_host() + request.path  # http://localhost:8000/auth/

    """Populate the WSKey object's parameters"""
    my_wskey = wskey.Wskey(
        key=key,
        secret=secret,
        options={
            'services': services,
            'redirect_uri': redirect_uri
        }
    )

    access_token = None

    """If an access_token is stored in the current session load it."""
    if request.session.get('access_token', None) != None:
        access_token = pickle.loads(request.session.get('access_token', None))

    """If the access_token we loaded is expired, we can't use it."""
    if access_token != None and access_token.is_expired():
        access_token = None

    """If there is a code parameter on the current URL, load it."""
    code = request.GET.get('code', None)

    """If there are error parameters on the current URL, load them."""
    error = request.GET.get('error', None)
    errorDescription = request.GET.get('error_description', None)

    if error != None:
        """If an error was returned, display it."""
        response.write('<p class="error">Error: ' + error + '<br>' + errorDescription + '</p>')

    elif access_token == None and code == None:
        """Initiate user authentication by executing a redirect to the IDM sign in page."""
        login_url = my_wskey.get_login_url(
            authenticating_institution_id=authenticating_institution_id,
            context_institution_id=context_institution_id
        )
        response['Location'] = login_url
        response.status_code = '303'

    elif access_token == None and code != None:
        """Request an access token using the user authentication code returned after the user authenticated"""
        """Then request a bibliographic record"""
        access_token = my_wskey.get_access_token_with_auth_code(
            code=code,
            authenticating_institution_id=authenticating_institution_id,
            context_institution_id=context_institution_id
        )

        if access_token.error_code == None:
            request.session['access_token'] = pickle.dumps(access_token)
            response.write('<p><strong>Access Token</strong> NOT FOUND in this session, so I requested a new one.</p>')

        response.write(format_access_token(access_token=access_token))

        if access_token.error_code == None:
            response.write(get_bib_record(access_token=access_token, wskey=my_wskey))

    elif access_token != None:
        """We already have an Access Token, so display the token and request a Bibliographic Record"""
        if access_token.error_code == None:
            response.write('<p><strong>Access Token</strong> found in this session, and it is still valid.</p>')

        response.write(format_access_token(access_token=access_token))

        if access_token.error_code == None:
            response.write(get_bib_record(access_token=access_token, wskey=my_wskey))

    return response


def format_access_token(access_token):
    """Display all the parameters of the Access Token"""
    print(access_token)

    ret = '<h2>Access Token</h2>'

    ret += '<table class="pure-table">'

    if access_token.error_code != None:
        ret += '<tr><td>Error Code</td><td>' + str(access_token.error_code) + '</td></tr>'
        ret += '<tr><td>Error Message</td><td>' + str(access_token.error_message) + '</td></tr>'
        ret += ('<tr><td>Error Url</td><td><pre>' +
                str(access_token.error_url).replace('?', '?\n').replace('&', '\n&') + '</pre></td></tr>')

    else:
        ret += '<tr><td>access_token</td><td>' + str(access_token.access_token_string) + '</td></tr>'
        ret += '<tr><td>token_type</td><td>' + str(access_token.type) + '</td></tr>'
        ret += '<tr><td>expires_at</td><td>' + str(access_token.expires_at) + '</td></tr>'
        ret += '<tr><td>expires_in</td><td>' + str(access_token.expires_in) + '</td></tr>'

        if access_token.user != None:
            ret += '<tr><td>principalID</td><td>' + str(access_token.user.principal_id) + '</td></tr>'
            ret += '<tr><td>principalIDNS</td><td>' + str(access_token.user.principal_idns) + '</td></tr>'
            ret += '<tr><td>contextInstitutionId</td><td>' + str(access_token.context_institution_id) + '</td></tr>'

        if access_token.refresh_token != None:
            ret += '<tr><td>refresh_token</td><td>' + str(access_token.refresh_token.refresh_token) + '</td></tr>'
            ret += '<tr><td>refresh_token_expires_at</td><td>' + str(
                access_token.refresh_token.expires_at) + '</td></tr>'
            ret += '<tr><td>refresh_token_expires_in</td><td>' + str(
                access_token.refresh_token.expires_in) + '</td></tr>'

    ret += '</table>'
    return ret


def get_bib_record(access_token, wskey):
    """Use an Access Token's User Parameter to request a Bibliographic Record"""
    request_url = (
        'https://worldcat.org/bib/data/823520553?' +
        'classificationScheme=LibraryOfCongress' +
        '&holdingLibraryCode=MAIN'
    )

    authorization_header = wskey.get_hmac_signature(
        method='GET',
        request_url=request_url,
        options={
            'user': access_token.user
        }
    )

    my_request = urllib2.Request(
        url=request_url,
        data=None,
        headers={'Authorization': authorization_header}
    )

    try:
        xml_result = urllib2.urlopen(my_request).read()

    except urllib2.HTTPError, e:
        xml_result = str(e)

    ret = '<h2>Bibliographic Record</h2>'
    ret += '<pre>' + xml_result.replace('<', '&lt;') + '</pre>'

    return ret