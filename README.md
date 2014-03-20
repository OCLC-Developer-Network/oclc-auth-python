OCLC Pythen Authentication Library
==================================

This library is a wrapper around the Web Service Authentication system used by OCLC web services.

Installation
------------

Download the file: `git clone https://github.com/OCLC-Developer-Network/oclc-auth-python.git`

Here is a description of the folders

* authliboclc - the authentication library
* djangoProject - the example Django project
* exampleAuthTokenDjangoApp - the example Django app for Use Authentication with Access Tokens
* tests - for authliboclc
* exampleHmacRequest.py - the example Python script for HMAC Authentication

Running the Examples
====================

###Server Side HMAC Authentication Example

1. Edit `exampleHmacRequest.py` to insert your:
    * key
    * secret
    * principalID
    * principalIDNS
    * authenticatingInstitutionID

1. Run from the command line:

   `python exampleHmacRequest.py`

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

###User Authentication and Access Token Django Example

For performing client side authentication using Access Tokens, we prepared an example using django. Note that
Access Tokens require Secure Socket Layer be implemented on the host.

First, we need to install these dependencies:

1. Install Django (see <a href="https://docs.djangoproject.com/en/1.6/intro/install/">Django Installation Guide</a>).<br>`sudo pip install django`</li>
1. To run SSL from localhost, install a <a href="https://github.com/teddziuba/django-sslserver">django-sslserver<a/>.<br>`sudo pip install django-sslserver`<br>
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

1. Edit `exampleAuthTokenDjangoApp/views.py` and insert your Key and Secret.
   Note that your WSKey must be configured with these parameters:
   * RedirectURI that matches the URI you are running the example from. For example, <strong>https://localhost:8000/auth/</strong>
   * Scopes. ie, <strong>WorldCatMetadataAPI</strong> for the Django example provided with this library.

1. Use runsslserver to start Django's SSL server from the root directory:

    `python manage.py runsslserver`

1. Direct your browser to `https://localhost:8000/auth/`.

1. If all goes well, you should see some authentication warnings (that's expected - we're running localhost with a self
signed CACERT). Click through these and you should see an authentication screen.

* Sign in with your userId and Password
* When prompted to allow access, click yes

You should see your access token details and a sample Bibliographic record, in XML format.

Using the Library
=================

HMAC Signature
--------------

HMAC Signatures are used when your server is requesting data from OCLC's server. Because this pattern uses a secret
and a key, it is never meant for client-side use. HMAC Signatures are discussed in detail on
<a href="http://www.oclc.org/developer/develop/authentication/hmac-signature.en.html">
OCLC's Developer Network</a>.

To use the authliboclc library to create a HMAC Signature, include the following libraries in your Python script:

<pre>
from authliboclc import wskey
from authliboclc import user
import urllib2
</pre>

You need to supply authentication parameters. OCLC Web Service Keys can be <a href="https://platform.worldcat.org/wskey">requested and managed here</a>.

<pre>
key = '{clientID}'
secret = '{secret}'
principalID = '{principalID}'
principalIDNS = '{principalIDNS}'
authenticatingInstitutionID = '{institutionID}'
</pre>

Next, you need to construction a request URL. OCLC Web Services <a href="http://www.oclc.org/developer/develop/web-services.en.html">are documented here</a>. For example, to request a Bibliographic Record, your URL request might look like this:

<pre>
requestUrl = 'https://worldcat.org/bib/data/823520553?classificationScheme=LibraryOfCongress&holdingLibraryCode=MAIN'
</pre>

Now you build your <strong>wskey</strong> and <strong>user</strong> objects. The options are meant for access token use and you do not need to add them for this example.
See the <a href="https://github.com/OCLC-Developer-Network/oclc-auth-python/blob/master/authliboclc/wskey.py">wskey.py</a> file in the <a href="https://github.com/OCLC-Developer-Network/oclc-auth-python/tree/master/authliboclc">authliboclc</a> library folder.

<pre>
myWskey = wskey.Wskey(**{
    'key': key,
    'secret': secret,
    'options': None})

myUser = user.User(**{
    'authenticatingInstitutionID': authenticatingInstitutionID,
    'principalID': principalID,
    'principalIDNS': principalIDNS
})
</pre>

Calculate the Authorization header:

<pre>
authorizationHeader = myWskey.getHMACSignature(**{
    'method': 'GET',
    'requestUrl': requestUrl,
    'options': {
        'user': myUser,
        'authParams': None}
})
</pre>

With our request URL and Authorization header prepared, we are ready to use Python's <strong>urllib2</strong>
library to make the GET request.

<pre>
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
</pre>

You should get a string containing an xml object, or an error message if a parameter is wrong or the WSKey is not configured properly.

User Authentication with Access Tokens
--------------------------------------

When performing User Authentication on the client side, an OAuth2 pattern must be followed. This requires providing a
web browser context for authentication to take place in. For most Python Web Applications, that context is provide by
the Django framework, which we used for our Access Token example.

Install the Django framework:

<pre>
sudo pip install django
</pre>

Install a test SSL server in localhost:

<pre>
sudo pip install django-sslserver
</pre>

You can run the django from the project root directory by typing:

<pre>
python manage.py runsslserver
</pre>

Point your browser to `https://localhost:8000/auth/` to see the output from the apps view.py file.

Optional: Instead of the test django-sslserver server, you can install <a href="http://blog.isotoma.com/2012/07/running-a-django-dev-instance-over-https/">Stunnel</a>. We leave that up to the experienced Python Developer.

Once you get your localhost SSL environment set up and working, you can use the <a>authliboclc</a> library to handle the access token and user authentication patterns.

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
    * contextInstitutionID
    * authenticatingInstitutionID
    * services (api service name, ie `WorldCatMetadataAPI` for the <a href="http://www.oclc.org/developer/develop/web-services/worldcat-metadata-api.en.html">Metadata API</a>
    * redirectUri (where your app runs on the web, i.e. `https://localhost:8000/auth/`

1. Create a wskey object:
   <pre>
   myWskey = wskey.Wskey(**{
       'key': key,
       'secret': secret,
       'options': {
           'services': ['service1' {,'service2',...} ],
           'redirectUri': redirectUri
       }
   })
   </pre>

1. Generate a login URL and redirect to it:
   <pre>
   loginUrl = myWskey.getLoginUrl(**{
        'authenticatingInstitutionId': '{your institutionId}',
        'contextInstitutionId': '{your institutionId}'
    })
    response['Location'] = loginUrl
    response.status_code = '303'
    </pre>

1. The user will be prompted to sign in with a UserId and Password. If they authenticate successfully, you will
receive back a url with a code parameter embedded in it. Parse out the code parameter to be used to request an Access Token.

####Use the Authorization Code to request an Access Token.

An Access Token is a unique string which the client will send to the web service in order to authenticate itself. Each
Access Token represents a particular application’s right to access set of web services, on behalf of a given user in
order to read or write data associated with a specific institution during a specific time period.

This library function takes the <strong>code</strong> and makes the Access Token request, returning the Access Token object.

    accessToken = myWskey.getAccessTokenWithAuthCode(**{
        'code': code,
        'authenticatingInstitutionId': '128807',
        'contextInstitutionId': '128807'
    })

The access token object has these parameters:

* accessTokenString
* type
* expiresAt (ISO 8601 time)
* expiresIn (int, seconds)
* user
    * principalID
    * principalIDNS
    * authenticatingInstitutionI
* contextInstitutionId
* errorCode

If you include <strong>refresh_token</strong> as one of the services, you will also get back a refresh token:

* refreshToken
    * refreshToken (the string value of the token)
    * expiresAt (ISO 8601 time)
    * expiresIn (int, seconds)


####Making requests with the Access Token

Our access token has a user object which contains a principalID and principalIDNS. We can use those parameters to make
a Bibliographic Record request. For example, let's retrieve the record for OCLC Number 823520553:

<pre>
requestUrl = (
    'https://worldcat.org/bib/data/823520553?' +
    'classificationScheme=LibraryOfCongress' +
    '&holdingLibraryCode=MAIN'
)
</pre>

Now we construct an authorization header using our Access Token's user parameter:

<pre>
authorizationHeader = wskey.getHMACSignature(**{
    'method': 'GET',
    'requestUrl': requestUrl,
    'options': {
        'user': accessToken.user
    }
})
</pre>

Finally, we make the request:

<pre>
myRequest = urllib2.Request(**{
    'url': requestUrl,
    'data': None,
    'headers': {'Authorization': authorizationHeader}
})

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
