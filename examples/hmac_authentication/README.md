###Server Side HMAC Authentication Example

1. Install the library:

   `pip install git+git:https://github.com/OCLC-Developer-Network/oclc-auth-python`

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