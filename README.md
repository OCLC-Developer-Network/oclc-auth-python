OCLC Python Authentication Library
==================================

This library is a wrapper around the Web Service Authentication system used by OCLC web services, written for Python. It works with versions 2.7 and 3 (up to 3.6)

Installation
------------
The easiest way to install is via pip:

`pip install git+git:https://github.com/OCLC-Developer-Network/oclc-auth-python`

Alternatively, clone the repository:

`git clone https://github.com/OCLC-Developer-Network/oclc-auth-python.git`

Install the library:

`sudo python setup.py install`


Running the Examples
====================

### Server Side HMAC Authentication Example

1. Change directories to `examples/hmac_authentication`

1. Edit `hmac_request_example.py` to insert your:
    * key
    * secret
    * principal_id
    * principal_idns
    * authenticating_institution_id
<br><br>
1. Run from the command line:

   `python hmac_request_example.py`

   You should get back an XML result if your WSKey is configured properly.

   <pre>
   &lt;?xml version="1.0" encoding="UTF-8"?>
       &lt;entry xmlns="http://www.w3.org/2005/Atom">
       &lt;content type="application/xml">
       &lt;response xmlns="http://worldcat.org/rb" mimeType="application/vnd.oclc.marc21+xml">
       &lt;record xmlns="http://www.loc.gov/MARC21/slim">
       &lt;leader>00000cam a2200000Ia 4500</leader>
       ...
   </pre>

### Getting an Access Token with Client Credentials Grant Example

1. Change directories to `examples/client_credentials_grant`

1. Edit `client_credentials_grant.py` to insert your:
    * key
    * secret
    * authenticating_institution_id
    * context_institution_id
<br><br>
1. Run from the command line:

   `python client_credentials_grant.py`

   You should get back an access token if your WSKey is configured properly.

   <pre>
   access token:  tk_xxx5KWq9w1Cc0dc5MrvIhFvdEZteylgsR7VT
   expires_in:    1199
   expires_at:    2014-09-09 15:22:49Z
   type:          bearer
   </pre>

   Or an error message if the key is not configured properly

   <pre>
   error_code:    401
   error_message: HTTP Error 401: Unauthorized
   error_url:     https://authn.sd00.worldcat.org/oauth2/accessToken?
                  grant_type=client_credentials&
                  authenticatingInstitutionId=128807&
                  contextInstitutionId=128807&
                  scope=WorldCatDiscoveryAPI
   </pre>

### User Authentication and Access Token Example

This example demonstrates how to retrieve an access token, and has the following features:
* Provides a basic HTTPS server
* Redirects a user to authenticate to retrieve an Access Code
* Uses the Access Code to retrieve an Access Token
* Stores the Access Token in a Session and manages a list of sessions using a simple flat file.
* Uses the Access Token to request a Bibliographic Record from OCLC.

To use the example:

1. Change directories to `examples/authentication_token`

1. Edit server.py to insert your WSKey parameters:
   <pre>
   KEY = '{clientID}'
   SECRET = '{secret}'
   </pre>

1. From the command line:

    `python server.py`

1. Navigate your browser to:

    `https://localhost:8000/auth/`

    Do not be concerned about "security warnings" - click through them. That is expected with the supplied, unsigned
    CACERT in server.pem. In production, you will use your institution's signed CACERT when implementing SSL.

### User Authentication and Access Token Django Example

For performing client side authentication using Access Tokens, we prepared an example using a popular framework, Django.
We show how to set up a simple Django App and implement SSL on the localhost for testing.

First, we need to install these dependencies:

1. Change directories to `examples/djangoProject`.

2. Install `pip` if you have not already - <a href="http://www.pip-installer.org/en/latest/">pip</a>. 

3. Install Django (see <a href="https://docs.djangoproject.com/en/1.6/intro/install/">Django Installation Guide</a>).

    `sudo pip install django`</li>

4. To run SSL from localhost, install a <a href="https://github.com/teddziuba/django-sslserver">django-sslserver</a>.

    `sudo pip install django-sslserver`<br>

    An alternate method popular with Django developers is to install <a href="http://blog.isotoma.com/2012/07/running-a-django-dev-instance-over-https/">Stunnel</a>.

   Note: if running stunnel, you should edit `djangoProject/settings.py` and remove the reference to <strong>sslserver</strong>:
   <pre>
       INSTALLED_APPS = (
           'django.contrib.admin',
           'django.contrib.auth',
           'django.contrib.contenttypes',
           'django.contrib.sessions',
           'django.contrib.messages',
           'django.contrib.staticfiles',
           'exampleAuthTokenDjangoApp',
           'sslserver', # remove if using Stunnel
       )
   </pre>

5. Edit `djangoProject/views.py` and insert your Key and Secret.
   Note that your WSKey must be configured with these parameters:
   * RedirectURI that matches the URI you are running the example from. For example, <strong>https://localhost:8000/auth/</strong>
   * Scopes. ie, <strong>WorldCatMetadataAPI</strong> for the Django example provided with this library.

6. Use runsslserver to start Django's SSL server from the `examples/authentication_token_with_django` directory:

    `python manage.py runsslserver`

7. Direct your browser to `https://localhost:8000/auth/`.

8. If all goes well, you should see some authentication warnings (that's expected - because runsslserver uses a self-signed CACERT). Click through the warning messages and you should see an authentication screen.

    * Sign in with your userId and Password
    * When prompted to allow access, click yes

	<br>
    You should see your access token details and a sample Bibliographic record, in XML format.

Using the Library
=================

HMAC Signature
--------------

Authentication for server side requests uses HMAC Signatures. Because this pattern uses a secret
and a key, it is never meant for client-side use. HMAC Signatures are discussed in detail at
<a href="http://www.oclc.org/developer/develop/authentication/hmac-signature.en.html">
OCLC Developer Network - Authentication</a>.

To use the `authliboclc` library to create a HMAC Signature, include the following libraries in your Python script:

<pre>
from authliboclc import wskey
from authliboclc import user
import urllib2
</pre>

You must supply authentication parameters. OCLC Web Service Keys can be <a href="https://platform.worldcat.org/wskey">requested and managed here</a>.

<pre>
key = '{clientID}'
secret = '{secret}'
principal_id = '{principalID}'
principal_idns = '{principalIDNS}'
authenticating_institution_id = '{institutionID}'
</pre>

Construct a request URL. See <a href="http://www.oclc.org/developer/develop/web-services.en.html">OCLC web services documentation</a>. For example, to request a Bibliographic Record:

<pre>
request_url = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN'
</pre>

Construct the <strong>wskey</strong> and <strong>user</strong> objects. 

<pre>
my_wskey = wskey.Wskey(
    key=key,
    secret=secret,
    options=None
)

my_user = user.User(
    authenticating_institution_id=authenticating_institution_id,
    principal_id=principal_id,
    principal_idns=principal_idns
)
</pre>

Note that the options parameter is for access token use and you do not need to add them for this example. For details, see the <a href="https://github.com/OCLC-Developer-Network/oclc-auth-python/blob/master/authliboclc/wskey.py">wskey.py</a> file in the <a href="https://github.com/OCLC-Developer-Network/oclc-auth-python/tree/master/authliboclc">authliboclc</a> library folder.

Calculate the Authorization header:

<pre>
authorization_header = my_wskey.get_hmac_signature(
    method='GET',
    request_url=request_url,
    options={
        'user': my_user,
        'auth_params': None}
)
</pre>

With our request URL and Authorization header prepared, we are ready to use Python's <strong>urllib2</strong>
library to make the GET request.

<pre>
my_request = urllib2.Request(
    url=request_url,
    data=None,
    headers={'Authorization': authorization_header}
)

try:
    xmlresult = urllib2.urlopen(myRequest).read()
    print(xmlresult)

except urllib2.HTTPError, e:
    print ('** ' + str(e) + ' **')
</pre>

You should get a string containing an xml object, or an error message if a parameter is wrong or the WSKey is not configured properly.

User Authentication with Access Tokens
--------------------------------------

The imports for working with the authentication library inside a Django view look like this:

<pre>
from django.http import HttpResponse
from authliboclc import wskey
import urllib2
</pre>

The authentication pattern is <a href="http://www.oclc.org/developer/develop/authentication/access-tokens.en.html">
described in detail</a> on the OCLC Developer Network. More specifically, we implemented the
<a href="http://www.oclc.org/developer/develop/authentication/access-tokens/explicit-authorization-code.en.html">
Explicit Authorization Code</a> pattern in the <strong>authliboclc</strong> library.

#### Request an Authorization Code.

An Authorization Code
is a unique string which is returned in the url after a user has successfully authenticated. The Authorization Code will then be
exchanged by the client to obtain Access Tokens:

1. You need to gather your authentication parameters:
    * key
    * secret
    * context_institution_id
    * authenticating_institution_id
    * services (api service name, ie `WorldCatMetadataAPI` for the <a href="http://www.oclc.org/developer/develop/web-services/worldcat-metadata-api.en.html">Metadata API</a>
    * redirect_uri (where your app runs on the web, i.e. `https://localhost:8000/auth/`

1. Create a wskey object:
   <pre>
   myWskey = wskey.Wskey(
       key=key,
       secret=secret,
       options={
           'services': ['service1' {,'service2',...} ],
           'redirect_uri': redirect_uri
       }
   )
   </pre>

1. Generate a login URL and redirect to it:
   <pre>
   login_url = myWskey.get_login_url(
        authenticating_institution_id='{your institutionId}',
        context_institution_id='{your institutionId}'
    )
    response['Location'] = login_url
    response.status_code = '303'
    </pre>

1. The user will be prompted to sign in with a UserId and Password. If they authenticate successfully, you will
receive back a url with a code parameter embedded in it. Parse out the code parameter to be used to request an Access Token.

#### Use the Authorization Code to request an Access Token.

An Access Token is a unique string which the client will send to the web service in order to authenticate itself. Each
Access Token represents a particular application’s right to access set of web services, on behalf of a given user in
order to read or write data associated with a specific institution during a specific time period.

This library function takes the <strong>code</strong> and makes the Access Token request, returning the Access Token object.

    access_token = myWskey.get_access_token_with_auth_code(
        code=code,
        authenticating_institution_id='128807',
        context_institution_id='128807'
    )

The access token object has these parameters:

* accessTokenString
* type
* expiresAt (ISO 8601 time)
* expiresIn (int, seconds)
* user
    * principal_id
    * principal_idns
    * authenticating_institution_id
* context_institution_id
* errorCode

If you include <strong>refresh_token</strong> as one of the services, you will also get back a refresh token:

* refreshToken
    * refreshToken (the string value of the token)
    * expiresAt (ISO 8601 time)
    * expiresIn (int, seconds)


#### Making requests with the Access Token

Our access token has a user object which contains a principalID and principalIDNS. We can use those parameters to make
a Bibliographic Record request. For example, let's retrieve the record for OCLC Number 823520553:

<pre>
request_url = (
    'https://worldcat.org/bib/data/823520553?' +
    'classificationScheme=LibraryOfCongress' +
    '&holdingLibraryCode=MAIN'
)
</pre>

Now we construct an authorization header using our Access Token's user parameter:

<pre>
authorization_header = wskey.get_hmac_signature(
    method='GET',
    request_url=request_url,
    options={
        'user': access_token.user
    }
)
</pre>

Finally, we make the request:

<pre>
myRequest = urllib2.Request(
    url=request_url,
    data=None,
    headers={'Authorization': authorization_header}
)

try:
    xmlResult = urllib2.urlopen(myRequest).read()

except urllib2.HTTPError, e:
    xmlResult = str(e)
</pre>

Resources
---------

* <a href="http://oclc.org/developer/home.en.html">OCLC Developer Network</a>
    * <a href="http://www.oclc.org/developer/develop/authentication.en.html">Authentication</a>
    * <a href="http://www.oclc.org/developer/develop/web-services.en.html">Web Services</a>
* <a href="https://platform.worldcat.org/wskey">Manage your OCLC API Keys</a>
* <a href="https://platform.worldcat.org/api-explorer/">OCLC's API Explorer</a>
