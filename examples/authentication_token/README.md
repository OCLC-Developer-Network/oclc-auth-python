###User Authentication and Access Token Example

This example demonstrates how to retrieve an access token, and has the following features:
* HTTP Secure authentication.
* Acquiring an Access Token.
* Storing the Access Token in a Session so the user doesn't have to authenticate twice.
* Using the Access Token to request a Bibliographic Record from OCLC.

1. Edit access_token.py to insert your WSKey parameters:

   `KEY = '{clientID}`
   `SECRET = '{secret}'`

1. From the command line:

    `python access_token.py`

1. Navigate your browser to:

    `https://localhost:8000/auth/`

    Do not be concerned about "security warnings" - click through them. The supplied, unsigned certificate is for
    testing purposes at the local host level only.