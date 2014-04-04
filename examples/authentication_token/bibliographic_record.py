import urllib2


class BibRecord():
    _access_token = None
    _wskey = None

    def __init__(self, access_token, wskey):
        self._access_token = access_token
        self._wskey = wskey

    def read(self):
        """Use an Access Token's User Parameter to request a Bibliographic Record"""
        request_url = (
            'https://worldcat.org/bib/data/823520553?' +
            'classificationScheme=LibraryOfCongress' +
            '&holdingLibraryCode=MAIN'
        )

        authorization_header = self._wskey.get_hmac_signature(
            method='GET',
            request_url=request_url,
            options={'user': self._access_token.user}
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

        return ''.join(['<h2>Bibliographic Record</h2><pre>', xml_result.replace('<', '&lt;'), '</pre>'])