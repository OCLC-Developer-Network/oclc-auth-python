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

import BaseHTTPServer
import ssl
from SimpleHTTPServer import SimpleHTTPRequestHandler
from authliboclc import wskey
from urlparse import urlparse, parse_qs
from session_handler import SessionHandler
from access_token_formatter import AccessTokenFormatter
from bibliographic_record import BibRecord

PORT = 8000

"""Authentication parameters."""
KEY = '{clientID}'
SECRET = '{secret}'
AUTHENTICATING_INSTITUTION_ID = '128807'  # default value for Sandbox institution
CONTEXT_INSTITUTION_ID = '128807'  # default value for Sandbox institution
SERVICES = ['WorldCatMetadataAPI', 'refresh_token']
REDIRECT_URI = 'https://localhost:8000/auth/'


class Request(SimpleHTTPRequestHandler):
    """This is a general purpose request handler. We focus on /auth/ and managing access tokens."""

    def do_GET(self):

        if KEY == '{clientID}':
            """The developer forgot to insert authentication parameters into the example."""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write('<h2>Please set the authentication parameters in ' +
                             '<span style="color:red">examples/authentication_token/server.py</span>, ' +
                             'lines 29 & 30.</h2>')
            return

        if (self.path[:6] != '/auth/'):
            """Handle other, non authentication requests here. For example, loading the favicon.ico"""
            return

        print "\n-- Handling a Request --"

        html = ("""<!doctype html>
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
        <h1>Authentication Token & Bibliographic Record</h1>
            """)

        """Populate the WSKey object's parameters"""
        my_wskey = wskey.Wskey(key=KEY, secret=SECRET, options={'services': SERVICES, 'redirect_uri': REDIRECT_URI})

        session_handler = SessionHandler(headers=self.headers)
        access_token = session_handler.get_access_token()

        """If there is a code parameter on the current URL, load it."""
        code = None
        if (self.path is not None):
            params = parse_qs(urlparse(self.path).query)
            if 'code' in params:
                code = params['code'][0]

        """If there are error parameters on the current URL, load them."""
        error = self.headers.get('error', None)
        error_description = self.headers.get('error_description', None)

        if access_token is None and code is None:
            """There is no access token and no authentication code. Initiate user authentication."""

            """Get the user authentication url"""
            login_url = my_wskey.get_login_url(
                authenticating_institution_id=AUTHENTICATING_INSTITUTION_ID,
                context_institution_id=CONTEXT_INSTITUTION_ID
            )

            """Redirect the browser to the login_url"""
            self.send_response(303)
            self.send_header('Location', login_url)
            self.end_headers()

            print "Requiring user to authenticate."

        else:

            if error is not None:
                """If an error was returned, display it."""
                html = ''.join([html, '<p class="error">Error: ', error, '<br>', error_description, '</p>'])

            if access_token is None and code is not None:
                """Request an access token using the user authentication code returned after the user authenticated"""
                """Then request a bibliographic record"""

                print "I now have an authentication code. I will request an access token."
                access_token = my_wskey.get_access_token_with_auth_code(
                    code=code,
                    authenticating_institution_id=AUTHENTICATING_INSTITUTION_ID,
                    context_institution_id=CONTEXT_INSTITUTION_ID
                )

                if access_token.error_code is None:
                    session_handler.save_access_token(access_token)
                    html = ''.join([html, '<p><strong>Access Token</strong> saved to session database.</p>'])

            if access_token is not None:
                """Display the token and request a Bibliographic Record"""
                print "Displaying access token parameters."
                if access_token.error_code is None and code is None:
                    html = ''.join([html, '<p><strong>Access Token</strong> retrieved from session database.</p>'])

                access_token_formatter = AccessTokenFormatter(access_token=access_token)
                html = ''.join([html, access_token_formatter.format()])

                if access_token.error_code is None:
                    print "Using Access Token to request a Bibliographic Record."
                    bib_record = BibRecord(access_token=access_token, wskey=my_wskey)
                    html = ''.join([html, bib_record.read()])

            html = ''.join([html, '</body></html>'])

            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.wfile.write(''.join([session_handler.cookie_header_output(), '\n']))
            self.end_headers()
            self.wfile.write(html)

        return


httpd = BaseHTTPServer.HTTPServer(('localhost', PORT), Request)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='server.pem', server_side=True)
print "\n\n\nStarting https server.\nNavigate your browser to " + \
      REDIRECT_URI + \
      "\nPress Ctrl-C to abort.\n---------------------------------------------------------"
httpd.serve_forever()
