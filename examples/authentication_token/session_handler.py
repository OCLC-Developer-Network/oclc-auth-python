import Cookie
import uuid
import pickle
import os.path
from time import time


class SessionHandler():
    """ This is a simple flat file session handler. In a production example, you might keep track of sessions
        in a mySQL database.

        The sessions are stored in a simple dict object
        {
            session id : pickled access token object,
            session id : pickled access token object,
            ...
        }
    """
    _cookie = None
    _headers = None
    _session_id = None
    _sessions = None
    _session = None
    _access_token = None

    def __init__(self, headers):
        self._headers = headers
        self.get_cookie()
        self.get_session()

    def get_cookie(self):
        """
            Determine if a cookie exists on the client. If so, load it. If not, create one by
            creating a new sessionid.
        """
        self._cookie = Cookie.SimpleCookie()
        print "Looking for a cookie in the header:"
        if self._headers.has_key('cookie'):
            print " - found one. "
            cookie_string = self._headers.get('cookie')
            self._cookie.load(cookie_string)
        else:
            print " - did not find one. Creating a new cookie."
            self._cookie['sessionid'] = uuid.uuid4()

    def get_session(self):
        """
            If a sessionid exists, retrieve the session information from the sessions.p file.
            Otherwise, write the current session to the sessions.p file.
        """
        self._session_id = self._cookie['sessionid'].value
        print "The session id is " + self._session_id

        """Load the sessions file from disk. If it does not exist, create one"""
        self._sessions = pickle.load(open('sessions.p', 'rb')) if os.path.isfile('sessions.p') else dict()
        print "Looking to see if the session id is stored in the sessions file:"
        if self._session_id in self._sessions:
            print " - found it."
            self._session = pickle.loads(self._sessions[self._session_id])
        else:
            print " - did not find it. Creating a new session"
            self._session = {'timestamp': time()}
            self._session.update({'id': self._session_id})

    def get_access_token(self):
        print "Looking for an access token in the current session:"

        """If an access_token is stored in the current session load it."""
        if self._session.get('access_token', None) is not None:
            print " - found one."
            self._access_token = pickle.loads(self._session.get('access_token', None))

            """If the access_token we loaded is expired, we can't use it."""
        elif self._access_token is not None and self._access_token.is_expired():
            print " - found one, but it was expired."
            self._access_token = None

        else:
            print " - did not find an access token."

        return self._access_token

    def cookie_header_output(self):
        return self._cookie.output()

    def save_access_token(self, access_token):
        print "Saving new access token to the session."
        self._session['access_token'] = pickle.dumps(access_token)
        self._sessions.update({self._session_id: pickle.dumps(self._session)})
        pickle.dump(self._sessions, open('sessions.p', 'wb'))