class AccessTokenFormatter():
    _access_token = None

    def __init__(self, access_token):
        self._access_token = access_token

    def format(self):
        """Display all the parameters of the Access Token"""
        ret = '<h2>Access Token</h2>'

        ret += '<table class="pure-table">'

        if self._access_token.error_code is not None:
            ret += '<tr><td>Error Code</td><td>' + str(self._access_token.error_code) + '</td></tr>'
            ret += '<tr><td>Error Message</td><td>' + str(self._access_token.error_message) + '</td></tr>'
            ret += ('<tr><td>Error Url</td><td><pre>' +
                    str(self._access_token.error_url).replace('?', '?\n').replace('&', '\n&') + '</pre></td></tr>')

        else:
            ret += '<tr><td>access_token</td><td>' + str(self._access_token.access_token_string) + '</td></tr>'
            ret += '<tr><td>token_type</td><td>' + str(self._access_token.type) + '</td></tr>'
            ret += '<tr><td>expires_at</td><td>' + str(self._access_token.expires_at) + '</td></tr>'
            ret += '<tr><td>expires_in</td><td>' + str(self._access_token.expires_in) + '</td></tr>'

            if self._access_token.user is not None:
                ret += '<tr><td>principalID</td><td>' + str(self._access_token.user.principal_id) + '</td></tr>'
                ret += '<tr><td>principalIDNS</td><td>' + str(self._access_token.user.principal_idns) + '</td></tr>'
                ret += '<tr><td>contextInstitutionId</td><td>' + str(
                    self._access_token.context_institution_id) + '</td></tr>'

            if self._access_token.refresh_token is not None:
                ret += '<tr><td>refresh_token</td><td>' + str(
                    self._access_token.refresh_token.refresh_token) + '</td></tr>'
                ret += '<tr><td>refresh_token_expires_at</td><td>' + str(
                    self._access_token.refresh_token.expires_at) + '</td></tr>'
                ret += '<tr><td>refresh_token_expires_in</td><td>' + str(
                    self._access_token.refresh_token.expires_in) + '</td></tr>'

        ret += '</table>'
        return ret