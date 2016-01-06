# -*- coding: utf-8 -*-
__doc__ = 'Load browser cookies into a cookiejar'

import os
import sys
import time
import glob
import http.cookiejar
import tempfile
try:
    import json
except ImportError:
    import simplejson as json
try:
    # should use pysqlite2 to read the cookies.sqlite on Windows
    # otherwise will raise the "sqlite3.DatabaseError: file is encrypted or is not a database" exception
    from pysqlite2 import dbapi2 as sqlite3
except ImportError:
    import sqlite3

import keyring
import pyaes
from pbkdf2 import PBKDF2



class BrowserCookieError(Exception):
    pass


def create_local_copy(cookie_file):
    """Make a local copy of the sqlite cookie database and return the new filename.
    This is necessary in case this database is still being written to while the user browses
    to avoid sqlite locking errors.
    """
    # check if cookie file exists
    if os.path.exists(cookie_file):
        # copy to random name in tmp folder
        tmp_cookie_file = tempfile.NamedTemporaryFile(suffix='.sqlite').name
        open(tmp_cookie_file, 'wb').write(open(cookie_file, 'rb').read())
        return tmp_cookie_file
    else:
        raise BrowserCookieError('Can not find cookie file at: ' + cookie_file)

class Chrome:
    def __init__(self, cookie_file=None):
        self.salt = b'saltysalt'
        self.iv = b' ' * 16
        self.length = 16
        if sys.platform == 'darwin':
            # running Chrome on OSX
            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
            my_pass = my_pass.encode('utf8')
            iterations = 1003
            cookie_file = cookie_file or os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies')

        elif sys.platform.startswith('linux'):
            # running Chrome on Linux
            my_pass = 'peanuts'.encode('utf8')
            iterations = 1
            cookie_file = cookie_file or os.path.expanduser('~/.config/google-chrome/Default/Cookies') or \
                                         os.path.expanduser('~/.config/chromium/Default/Cookies') or \
                                         os.path.expanduser('~/.config/google-chrome-beta/Default/Cookies')

        else:
            # XXX need to add Chrome on Windows support
            raise BrowserCookieError("Currently only Chrome support for Linux and OSX.")

        self.key = PBKDF2(my_pass, self.salt, iterations=iterations).read(self.length)
        self.tmp_cookie_file = create_local_copy(cookie_file)

    def __del__(self):
        # remove temporary backup of sqlite cookie database
        if (hasattr(self, 'tmp_cookie_file')): #if there was an error till here
            os.remove(self.tmp_cookie_file)

    def __str__(self):
        return 'chrome'


    def load(self):
        """Load sqlite cookies into a cookiejar
        """
        con = sqlite3.connect(self.tmp_cookie_file)
        cur = con.cursor()
        cur.execute('SELECT host_key, path, secure, expires_utc, name, value, encrypted_value FROM cookies;')
        cj = http.cookiejar.CookieJar()
        for item in cur.fetchall():
            host, path, secure, expires, name = item[:5]
            value = self._decrypt(item[5], item[6])
            c = create_cookie(host, path, secure, expires, name, value)
            cj.set_cookie(c)
        con.close()
        return cj


    def _decrypt(self, value, encrypted_value):
        """Decrypt encoded cookies
        """
        if value or (encrypted_value[:3] != b'v10'):
            return value

        # Encrypted cookies should be prefixed with 'v10' according to the
        # Chromium code. Strip it off.
        encrypted_value = encrypted_value[3:]
        encrypted_value_half_len = int(len(encrypted_value) / 2)

        # Strip padding by taking off number indicated by padding
        # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
        # You'll need to change this function to use ord() for python2.
        def clean(x):
            trailing = x[-1]
            decoded = x.decode()
            return decoded[:-trailing]

        cipher = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(self.key, self.iv))
        decrypted = cipher.feed(encrypted_value[:encrypted_value_half_len])
        decrypted += cipher.feed(encrypted_value[encrypted_value_half_len:])
        decrypted += cipher.feed()
        return decrypted.decode("utf-8")



class Firefox:
    def __init__(self, cookie_file=None):
        cookie_file = cookie_file or self.find_cookie_file()
        self.tmp_cookie_file = create_local_copy(cookie_file)
        # current sessions are saved in sessionstore.js
        self.session_file = os.path.join(os.path.dirname(cookie_file), 'sessionstore.js')

    def __del__(self):
        # remove temporary backup of sqlite cookie database
        os.remove(self.tmp_cookie_file)

    def __str__(self):
        return 'firefox'


    def find_cookie_file(self):
        if sys.platform == 'darwin':
            cookie_files = glob.glob(os.path.expanduser(r'~\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\cookies.sqlite'))
        elif sys.platform.startswith('linux'):
            cookie_files = glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default/cookies.sqlite'))
        elif sys.platform == 'win32':
            cookie_files = glob.glob(os.path.join(os.environ.get('PROGRAMFILES', ''), 'Mozilla Firefox/profile/cookies.sqlite')) or \
                           glob.glob(os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Mozilla Firefox/profile/cookies.sqlite'))
        else:
            raise BrowserCookieError('Unsupported operating system: ' + sys.platform)
        if cookie_files:
            return cookie_files[0]
        else:
            raise BrowserCookieError('Failed to find Firefox cookie')


    def load(self):
        con = sqlite3.connect(self.tmp_cookie_file)
        cur = con.cursor()
        cur.execute('select host, path, isSecure, expiry, name, value from moz_cookies')

        cj = http.cookiejar.CookieJar()
        for item in cur.fetchall():
            c = create_cookie(*item)
            cj.set_cookie(c)
        con.close()

        if os.path.exists(self.session_file):
            try:
                json_data = json.loads(open(self.session_file, 'rb').read())
            except ValueError as e:
                print('Error parsing firefox session JSON:', str(e))
            else:
                expires = str(int(time.time()) + 3600 * 24 * 7)
                for window in json_data.get('windows', []):
                    for cookie in window.get('cookies', []):
                        c = create_cookie(cookie.get('host', ''), cookie.get('path', ''), False, expires, cookie.get('name', ''), cookie.get('value', ''))
                        cj.set_cookie(c)

        return cj


def create_cookie(host, path, secure, expires, name, value):
    """Shortcut function to create a cookie
    """
    return http.cookiejar.Cookie(0, name, value, None, False, host, host.startswith('.'), host.startswith('.'), path, True, secure, expires, False, None, None, {})


def chrome(cookie_file=None):
    """Returns a cookiejar of the cookies used by Chrome
    """
    return Chrome(cookie_file).load()


def firefox(cookie_file=None):
    """Returns a cookiejar of the cookies and sessions used by Firefox
    """
    return Firefox(cookie_file).load()


def load():
    """Try to load cookies from all supported browsers and return combined cookiejar
    """
    cj = http.cookiejar.CookieJar()
    for cookie_fn in [chrome, firefox]:
        try:
            for cookie in cookie_fn():
                cj.set_cookie(cookie)
        except BrowserCookieError:
            pass
    return cj

def load_cookie_dict(browser_name, domain_name, cookie_file=None):
    """Load cookies for the browser based on the given browser_name parameter
    and return a dictionary containing key/value pairs for cookies for the
    domain with the given domain_name. browser_name must either be chrome
    or firefox.
    """
    # Load cookies based on browser
    if browser_name.lower() == "chrome":
        cj = chrome(cookie_file)
    elif browser_name.lower() == "firefox":
        cj = firefox(cookie_file)
    else:
        raise BrowserCookieError('Unsupported browser: ' + browser_name)
    # Now filter by domain
    cookie_dict = {}
    for cookie in cj:
        if domain_name in cookie.domain:
            cookie_dict[cookie.name] = cookie.value
    return cookie_dict
