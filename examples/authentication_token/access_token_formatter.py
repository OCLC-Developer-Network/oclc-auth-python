from cStringIO import StringIO


class AccessTokenFormatter():
    _access_token = None

    def __init__(self, access_token):
        self._access_token = access_token

    def format(self):
        """Display all the parameters of the Access Token"""
        ret = StringIO()
        ret.write('<h2>Access Token</h2>')

        ret.write('<table class="pure-table">')

        if self._access_token.error_code is not None:
            ret.write('<tr><td>Error Code</td><td>')
            ret.write(str(self._access_token.error_code))
            ret.write('</td></tr>')
            ret.write('<tr><td>Error Message</td><td>')
            ret.write(str(self._access_token.error_message))
            ret.write('</td></tr>')
            ret.write('<tr><td>Error Url</td><td><pre>')
            ret.write(str(self._access_token.error_url).replace('?', '?\n').replace('&', '\n&'))
            ret.write('</pre></td></tr>')

        else:

            ret.write('<tr><td>access_token</td><td>')
            ret.write(str(self._access_token.access_token_string))
            ret.write('</td></tr>')
            ret.write('<tr><td>token_type</td><td>')
            ret.write(str(self._access_token.type))
            ret.write('</td></tr>')
            ret.write('<tr><td>expires_at</td><td>')
            ret.write(str(self._access_token.expires_at))
            ret.write('</td></tr>')
            ret.write('<tr><td>expires_in</td><td>')
            ret.write(str(self._access_token.expires_in))
            ret.write('</td></tr>')

            if self._access_token.user is not None:
                ret.write('<tr><td>principalID</td><td>')
                ret.write(str(self._access_token.user.principal_id))
                ret.write('</td></tr>')
                ret.write('<tr><td>principalIDNS</td><td>')
                ret.write(str(self._access_token.user.principal_idns))
                ret.write('</td></tr>')
                ret.write('<tr><td>contextInstitutionId</td><td>')
                ret.write(str(self._access_token.context_institution_id))
                ret.write('</td></tr>')

            if self._access_token.refresh_token is not None:
                ret.write('<tr><td>refresh_token</td><td>')
                ret.write(str(self._access_token.refresh_token.refresh_token))
                ret.write('</td></tr>')
                ret.write('<tr><td>refresh_token_expires_at</td><td>')
                ret.write(str(self._access_token.refresh_token.expires_at))
                ret.write('</td></tr>')
                ret.write('<tr><td>refresh_token_expires_in</td><td>')
                ret.write(str(self._access_token.refresh_token.expires_in))
                ret.write('</td></tr>')

        ret.write('</table>')
        return ret.getvalue()