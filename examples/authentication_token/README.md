###User Authentication and Access Token Example

This example demonstrates how to retrieve an access token, and has the following features:
* Provides a basic HTTPS server
* Redirects a user to authenticate to retrieve an Access Code
* Uses the Access Code to retrieve an Access Token
* Stores the Access Token in a Session and manages a list of sessions using a simple flat file.
* Uses the Access Token to request a Bibliographic Record from OCLC.

To use the example:

1. Change directories to `examples/authentication_token`

1. Edit access_token.py to insert your WSKey parameters:
   <pre>
   KEY = '{clientID}'
   SECRET = '{secret}'
   </pre>

1. From the command line:

    `python access_token.py`

1. Navigate your browser to:

    `https://localhost:8000/auth/`

    Do not be concerned about "security warnings" - click through them. That is expected with the supplied, unsigned
    CACERT in server.pem. In production, you will use your institution's signed CACERT when implementing SSL.