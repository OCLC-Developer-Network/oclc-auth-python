###User Authentication and Access Token Django Example

For performing client side authentication using Access Tokens, we prepared an example using django. Note that
Access Tokens require Secure Socket Layer be implemented on the host.

Get the repo and install the library:

1. Clone the repository:

   `git clone https://github.com/OCLC-Developer-Network/oclc-auth-python.git`

1. Install the library:

   `sudo python setup.py install`

First, we need to install these dependencies:

1. Change directories to `examples/djangoProject`.

1. Install `pip` if you have not already - <a href="http://www.pip-installer.org/en/latest/">pip</a>. 

1. Install Django (see <a href="https://docs.djangoproject.com/en/1.6/intro/install/">Django Installation Guide</a>).

    `sudo pip install django`</li>

1. To run SSL from localhost, install a <a href="https://github.com/teddziuba/django-sslserver">django-sslserver</a>.

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

1. Edit `djangoProject/views.py` and insert your Key and Secret.
   Note that your WSKey must be configured with these parameters:
   * RedirectURI that matches the URI you are running the example from. For example, <strong>https://localhost:8000/auth/</strong>
   * Scopes. ie, <strong>WorldCatMetadataAPI</strong> for the Django example provided with this library.

1. Use runsslserver to start Django's SSL server from the `examples/authentication_token_with_django` directory:

    `python manage.py runsslserver`

1. Direct your browser to `https://localhost:8000/auth/`.

1. If all goes well, you should see some authentication warnings (that's expected - because runsslserver uses a self-signed CACERT). Click through the warning messages and you should see an authentication screen.

    * Sign in with your userId and Password
    * When prompted to allow access, click yes

	<br>
    You should see your access token details and a sample Bibliographic record, in XML format.
