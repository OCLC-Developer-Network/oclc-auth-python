###Server Side Client Credentials Grant Example

1. Clone the repository:

   `git clone https://github.com/OCLC-Developer-Network/oclc-auth-python.git`

1. Install the library:

   `sudo python setup.py install`

1. Change directories to `examples/client_credentials grant`

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