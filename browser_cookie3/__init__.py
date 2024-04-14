# -*- coding: utf-8 -*-

import base64
import configparser
import contextlib
import glob
import http.cookiejar
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Union

if sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
    try:
        import jeepney
        from jeepney.io.blocking import open_dbus_connection
        USE_DBUS_LINUX = False
    except ImportError:
        import dbus
        USE_DBUS_LINUX = True

# external dependencies
import lz4.block

__doc__ = 'Load browser cookies into a cookiejar'

CHROMIUM_DEFAULT_PASSWORD = b'peanuts'


class BrowserCookieError(Exception):
    pass


def _windows_group_policy_path():
    # we know that we're running under windows at this point so it's safe to do these imports
    from winreg import (HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ,
                        ConnectRegistry, OpenKeyEx, QueryValueEx)
    try:
        root = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        policy_key = OpenKeyEx(root, r"SOFTWARE\Policies\Google\Chrome")
        user_data_dir, type_ = QueryValueEx(policy_key, "UserDataDir")
        if type_ == REG_EXPAND_SZ:
            user_data_dir = os.path.expandvars(user_data_dir)
        elif type_ != REG_SZ:
            return None
    except OSError:
        return None
    return os.path.join(user_data_dir, "Default", "Cookies")


# Code adapted slightly from https://github.com/Arnie97/chrome-cookies
def _crypt_unprotect_data(
        cipher_text=b'', entropy=b'', reserved=None, prompt_struct=None, is_key=False
):
    # we know that we're running under windows at this point so it's safe to try these imports
    import ctypes
    import ctypes.wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ('cbData', ctypes.wintypes.DWORD),
            ('pbData', ctypes.POINTER(ctypes.c_char))
        ]

    blob_in, blob_entropy, blob_out = map(
        lambda x: DataBlob(len(x), ctypes.create_string_buffer(x)),
        [cipher_text, entropy, b'']
    )
    desc = ctypes.c_wchar_p()

    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), ctypes.byref(
                desc), ctypes.byref(blob_entropy),
            reserved, prompt_struct, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(
                blob_out)
    ):
        raise RuntimeError('Failed to decrypt the cipher text with DPAPI')

    description = desc.value
    buffer_out = ctypes.create_string_buffer(int(blob_out.cbData))
    ctypes.memmove(buffer_out, blob_out.pbData, blob_out.cbData)
    map(ctypes.windll.kernel32.LocalFree, [desc, blob_out.pbData])
    if is_key:
        return description, buffer_out.raw
    else:
        return description, buffer_out.value


def _get_osx_keychain_password(osx_key_service, osx_key_user):
    """Retrieve password used to encrypt cookies from OSX Keychain"""

    cmd = ['/usr/bin/security', '-q', 'find-generic-password',
           '-w', '-a', osx_key_user, '-s', osx_key_service]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        return CHROMIUM_DEFAULT_PASSWORD     # default password, probably won't work
    return out.strip()


def _expand_win_path(path: Union[dict, str]):
    if not isinstance(path, dict):
        path = {'path': path, 'env': 'APPDATA'}
    return os.path.join(os.getenv(path['env'], ''), path['path'])


def _expand_paths_impl(paths: list, os_name: str):
    """Expands user paths on Linux, OSX, and windows"""

    os_name = os_name.lower()
    assert os_name in ['windows', 'osx', 'linux']

    if not isinstance(paths, list):
        paths = [paths]

    if os_name == 'windows':
        paths = map(_expand_win_path, paths)
    else:
        paths = map(os.path.expanduser, paths)

    for path in paths:
        # glob will return results in arbitrary order. sorted() is use to make output predictable.
        for i in sorted(glob.glob(path)):
            # can use return here without using `_expand_paths()` below.
            yield i
            # but using generator can be useful if we plan to parse all `Cookies` files later.


def _expand_paths(paths: list, os_name: str):
    return next(_expand_paths_impl(paths, os_name), None)


def _normalize_genarate_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    channel = channel or ['']
    if not isinstance(channel, list):
        channel = [channel]
    if not isinstance(paths, list):
        paths = [paths]
    return paths, channel


def _genarate_nix_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on *nix systems."""

    paths, channel = _normalize_genarate_paths_chromium(paths, channel)
    genararated_paths = []
    for chan in channel:
        for path in paths:
            genararated_paths.append(path.format(channel=chan))
    return genararated_paths


def _genarate_win_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on windows"""

    paths, channel = _normalize_genarate_paths_chromium(paths, channel)
    genararated_paths = []
    for chan in channel:
        for path in paths:
            genararated_paths.append(
                {'env': 'APPDATA', 'path': '..\\Local\\' + path.format(channel=chan)})
            genararated_paths.append(
                {'env': 'LOCALAPPDATA', 'path': path.format(channel=chan)})
            genararated_paths.append(
                {'env': 'APPDATA', 'path': path.format(channel=chan)})
    return genararated_paths


def _text_factory(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data


class _JeepneyConnection:
    def __init__(self, object_path, bus_name, interface):
        self.__dbus_address = jeepney.DBusAddress(
            object_path, bus_name, interface)

    def __enter__(self):
        self.__connection = open_dbus_connection()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.__connection.close()

    def close(self):
        self.__connection.close()

    def call_method(self, method_name, signature=None, *args):
        method = jeepney.new_method_call(
            self.__dbus_address, method_name, signature, args)
        response = self.__connection.send_and_get_reply(method)
        if response.header.message_type == jeepney.MessageType.error:
            raise RuntimeError(response.body[0])
        return response.body[0] if len(response.body) == 1 else response.body


class _LinuxPasswordManager:
    """Retrieve password used to encrypt cookies from KDE Wallet or SecretService"""

    _APP_ID = 'browser-cookie3'

    def __init__(self, use_dbus):
        if use_dbus:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_dbus,
                'secretstorage': self.__get_secretstorage_item_dbus
            }
        else:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_jeepney,
                'secretstorage': self.__get_secretstorage_item_jeepney
            }

    def get_password(self, os_crypt_name):
        try:
            return self.__get_secretstorage_password(os_crypt_name)
        except RuntimeError:
            pass
        try:
            return self.__methods_map.get('kwallet')(os_crypt_name)
        except RuntimeError:
            pass
        # try default peanuts password, probably won't work
        return CHROMIUM_DEFAULT_PASSWORD

    def __get_secretstorage_password(self, os_crypt_name):
        schemas = ['chrome_libsecret_os_crypt_password_v2',
                   'chrome_libsecret_os_crypt_password_v1']
        for schema in schemas:
            try:
                return self.__methods_map.get('secretstorage')(schema, os_crypt_name)
            except RuntimeError:
                pass
        raise RuntimeError(f'Can not find secret for {os_crypt_name}')

    def __get_secretstorage_item_dbus(self, schema: str, application: str):
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                secret_service = dbus.Interface(
                    connection.get_object(
                        'org.freedesktop.secrets', '/org/freedesktop/secrets', False),
                    'org.freedesktop.Secret.Service',
                )
            except dbus.exceptions.DBusException:
                raise RuntimeError(
                    "The name org.freedesktop.secrets was not provided by any .service files")
            object_path = secret_service.SearchItems({
                'xdg:schema': schema,
                'application': application,
            })
            object_path = list(filter(lambda x: len(x), object_path))
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            object_path = object_path[0][0]

            secret_service.Unlock([object_path])
            _, session = secret_service.OpenSession(
                'plain', dbus.String('', variant_level=1))
            _, _, secret, _ = secret_service.GetSecrets(
                [object_path], session)[object_path]
            return bytes(secret)

    def __get_kdewallet_password_dbus(self, os_crypt_name):
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                kwalletd5_object = connection.get_object(
                    'org.kde.kwalletd5', '/modules/kwalletd5', False)
            except dbus.exceptions.DBusException:
                raise RuntimeError(
                    "The name org.kde.kwalletd5 was not provided by any .service files")
            kwalletd5 = dbus.Interface(kwalletd5_object, 'org.kde.KWallet')
            handle = kwalletd5.open(
                kwalletd5.networkWallet(), dbus.Int64(0), self._APP_ID)
            if not kwalletd5.hasFolder(handle, folder, self._APP_ID):
                kwalletd5.close(handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            password = kwalletd5.readPassword(
                handle, folder, key, self._APP_ID)
            kwalletd5.close(handle, False, self._APP_ID)
            return password.encode('utf-8')

    def __get_secretstorage_item_jeepney(self, schema, application):
        args = ['/org/freedesktop/secrets', 'org.freedesktop.secrets',
                'org.freedesktop.Secret.Service']
        with _JeepneyConnection(*args) as connection:
            object_path = connection.call_method(
                'SearchItems', 'a{ss}', {'xdg:schema': schema, 'application': application})
            object_path = list(filter(lambda x: len(x), object_path))
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            object_path = object_path[0][0]
            connection.call_method('Unlock', 'ao', [object_path])
            _, session = connection.call_method(
                'OpenSession', 'sv', 'plain', ('s', ''))
            _, _, secret, _ = connection.call_method(
                'GetSecrets', 'aoo', [object_path], session)[object_path]
            return secret

    def __get_kdewallet_password_jeepney(self, os_crypt_name):
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        with _JeepneyConnection('/modules/kwalletd5', 'org.kde.kwalletd5', 'org.kde.KWallet') as connection:
            network_wallet = connection.call_method('networkWallet')
            handle = connection.call_method(
                'open', 'sxs', network_wallet, 0, self._APP_ID)
            has_folder = connection.call_method(
                'hasFolder', 'iss', handle, folder, self._APP_ID)
            if not has_folder:
                connection.call_method(
                    'close', 'ibs', handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            password = connection.call_method(
                'readPassword', 'isss', handle, folder, key, self._APP_ID)
            connection.call_method('close', 'ibs', handle, False, self._APP_ID)
            return password.encode('utf-8')


class _DatabaseConnetion():
    def __init__(self, database_file: os.PathLike, try_legacy_first: bool = False):
        self.__database_file = database_file
        self.__temp_cookie_file = None
        self.__connection = None
        self.__methods = [
            self.__sqlite3_connect_readonly,
            self.__get_connection_legacy,
        ]
        if try_legacy_first:
            self.__methods.reverse()

    def __enter__(self):
        return self.get_connection()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __check_connection_ok(self, connection):
        try:
            connection.cursor().execute('select 1 from sqlite_master')
            return True
        except sqlite3.OperationalError:
            return False

    def __sqlite3_connect_readonly(self):
        uri = Path(self.__database_file).absolute().as_uri()
        for options in ('?mode=ro', '?mode=ro&nolock=1', '?mode=ro&immutable=1'):
            try:
                con = sqlite3.connect(uri + options, uri=True)
            except sqlite3.OperationalError:
                continue
            if self.__check_connection_ok(con):
                return con

    def __get_connection_legacy(self):
        self.__temp_cookie_file = tempfile.NamedTemporaryFile(
            suffix='.sqlite').name
        shutil.copyfile(self.__database_file, self.__temp_cookie_file)
        con = sqlite3.connect(self.__temp_cookie_file)
        if self.__check_connection_ok(con):
            return con

    def get_connection(self):
        if self.__connection:
            return self.__connection
        for method in self.__methods:
            con = method()
            if con is not None:
                self.__connection = con
                return con
        raise BrowserCookieError('Unable to read database file')

    def cursor(self):
        return self.connection().cursor()

    def close(self):
        if self.__connection:
            self.__connection.close()
        if self.__temp_cookie_file:
            try:
                os.remove(self.__temp_cookie_file)
            except Exception:
                pass


class FirefoxBased:
    """Superclass for Firefox based browsers"""

    def __init__(self, browser_name, cookie_file=None, domain_name="", **kwargs):
        self.browser_name = browser_name
        self.cookie_file = cookie_file or self.__find_cookie_file(**kwargs)
        # current sessions are saved in sessionstore.js
        self.session_file = os.path.join(
            os.path.dirname(self.cookie_file), 'sessionstore.js')
        self.session_file_lz4 = os.path.join(os.path.dirname(
            self.cookie_file), 'sessionstore-backups', 'recovery.jsonlz4')
        # domain name to filter cookies by
        self.domain_name = domain_name

    def __str__(self):
        return self.browser_name

    @staticmethod
    def get_default_profile(user_data_path):
        config = configparser.ConfigParser()
        profiles_ini_path = glob.glob(os.path.join(
            user_data_path + '**', 'profiles.ini'))
        fallback_path = user_data_path + '**'

        if not profiles_ini_path:
            return fallback_path

        profiles_ini_path = profiles_ini_path[0]
        config.read(profiles_ini_path, encoding="utf8")

        profile_path = None
        for section in config.sections():
            if section.startswith('Install'):
                profile_path = config[section].get('Default')
                break
            # in ff 72.0.1, if both an Install section and one with Default=1 are present, the former takes precedence
            elif config[section].get('Default') == '1' and not profile_path:
                profile_path = config[section].get('Path')

        for section in config.sections():
            # the Install section has no relative/absolute info, so check the profiles
            if config[section].get('Path') == profile_path:
                absolute = config[section].get('IsRelative') == '0'
                return profile_path if absolute else os.path.join(os.path.dirname(profiles_ini_path), profile_path)

        return fallback_path

    def __expand_and_check_path(self, paths: Union[str, List[str], Dict[str, str], List[Dict[str, str]]]) -> str:
        """Expands a path to a list of paths and returns the first one that exists"""
        if not isinstance(paths, list):
            paths = [paths]
        for path in paths:
            if isinstance(path, dict):
                expanded = _expand_win_path(path)
            else:
                expanded = os.path.expanduser(path)
            if os.path.isdir(expanded):
                return expanded
        raise BrowserCookieError(
            f'Could not find {self.browser_name} profile directory')

    def __find_cookie_file(self, linux_data_dirs=None, windows_data_dirs=None, osx_data_dirs=None):
        cookie_files = []

        if sys.platform == 'darwin':
            user_data_path = self.__expand_and_check_path(osx_data_dirs)
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            user_data_path = self.__expand_and_check_path(linux_data_dirs)
        elif sys.platform == 'win32':
            user_data_path = self.__expand_and_check_path(windows_data_dirs)
        else:
            raise BrowserCookieError(
                'Unsupported operating system: ' + sys.platform)

        cookie_files = glob.glob(os.path.join(FirefoxBased.get_default_profile(user_data_path), 'cookies.sqlite')) \
            or cookie_files

        if cookie_files:
            return cookie_files[0]
        else:
            raise BrowserCookieError(
                f'Failed to find {self.browser_name} cookie file')

    @staticmethod
    def __create_session_cookie(cookie_json):
        return create_cookie(cookie_json.get('host', ''), cookie_json.get('path', ''),
                             cookie_json.get('secure', False), None,
                             cookie_json.get('name', ''), cookie_json.get(
                                 'value', ''),
                             cookie_json.get('httponly', False))

    def __add_session_cookies(self, cj):
        if not os.path.exists(self.session_file):
            return
        try:
            with open(self.session_file, 'rb') as file_obj:
                json_data = json.load(file_obj)
        except ValueError as e:
            print(f'Error parsing {self.browser_name} session JSON:', str(e))
        else:
            for window in json_data.get('windows', []):
                for cookie in window.get('cookies', []):
                    if self.domain_name == '' or self.domain_name in cookie.get('host', ''):
                        cj.set_cookie(
                            FirefoxBased.__create_session_cookie(cookie))

    def __add_session_cookies_lz4(self, cj):
        if not os.path.exists(self.session_file_lz4):
            return
        try:
            with open(self.session_file_lz4, 'rb') as file_obj:
                file_obj.read(8)
                json_data = json.loads(lz4.block.decompress(file_obj.read()))
        except ValueError as e:
            print(
                f'Error parsing {self.browser_name} session JSON LZ4:', str(e))
        else:
            for cookie in json_data.get('cookies', []):
                if self.domain_name == '' or self.domain_name in cookie.get('host', ''):
                    cj.set_cookie(FirefoxBased.__create_session_cookie(cookie))

    def load(self):
        cj = http.cookiejar.CookieJar()
        # firefoxbased seems faster with legacy mode
        with _DatabaseConnetion(self.cookie_file, True) as con:
            cur = con.cursor()
            cur.execute('select host, path, isSecure, expiry, name, value, isHttpOnly from moz_cookies '
                        'where host like ?', ('%{}%'.format(self.domain_name),))

            for item in cur.fetchall():
                host, path, secure, expires, name, value, http_only = item
                c = create_cookie(host, path, secure, expires,
                                  name, value, http_only)
                cj.set_cookie(c)

        self.__add_session_cookies(cj)
        self.__add_session_cookies_lz4(cj)

        return cj


class Firefox(FirefoxBased):
    """Class for Firefox"""

    def __init__(self, cookie_file=None, domain_name=""):
        args = {
            'linux_data_dirs': [
                '~/snap/firefox/common/.mozilla/firefox',
                '~/.mozilla/firefox'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': r'Mozilla\Firefox'},
                {'env': 'LOCALAPPDATA', 'path': r'Mozilla\Firefox'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/Firefox'
            ]
        }
        super().__init__('Firefox', cookie_file, domain_name, **args)


class LibreWolf(FirefoxBased):
    """Class for LibreWolf"""

    def __init__(self, cookie_file=None, domain_name=""):
        args = {
            'linux_data_dirs': [
                '~/snap/librewolf/common/.librewolf',
                '~/.librewolf'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': 'librewolf'},
                {'env': 'LOCALAPPDATA', 'path': 'librewolf'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/librewolf'
            ]
        }
        super().__init__('LibreWolf', cookie_file, domain_name, **args)


class Safari:
    """Class for Safari"""

    APPLE_TO_UNIX_TIME = 978307200
    NEW_ISSUE_URL = 'https://github.com/borisbabic/browser_cookie3/issues/new'
    NEW_ISSUE_MESSAGE = f'Page format changed.\nPlease create a new issue on: {NEW_ISSUE_URL}'
    safari_cookies = [
        '~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies',
        '~/Library/Cookies/Cookies.binarycookies'
    ]

    def __init__(self, cookie_file=None, domain_name="") -> None:
        self.__offset = 0
        self.__domain_name = domain_name
        self.__buffer = None
        self.__open_file(cookie_file)
        self.__parse_header()

    def __del__(self):
        if self.__buffer:
            self.__buffer.close()

    def __open_file(self, cookie_file):
        cookie_file = cookie_file or _expand_paths(self.safari_cookies, 'osx')
        if not cookie_file:
            raise BrowserCookieError('Can not find Safari cookie file')
        self.__buffer = open(cookie_file, 'rb')

    def __read_file(self, size: int, offset: int = None):
        if offset is not None:
            self.__offset = offset
        self.__buffer.seek(self.__offset)
        self.__offset += size
        return BytesIO(self.__buffer.read(size))

    def __parse_header(self):
        assert self.__buffer.read(4) == b'cook', 'Not a safari cookie file'
        self.__total_page = struct.unpack('>I', self.__buffer.read(4))[0]

        self.__page_sizes = []
        for _ in range(self.__total_page):
            self.__page_sizes.append(struct.unpack(
                '>I', self.__buffer.read(4))[0])

    @staticmethod
    def __read_until_null(file: BytesIO, decode: bool = True):
        data = []
        while True:
            byte = file.read(1)
            if byte == b'\x00':
                break
            data.append(byte)
        data = b''.join(data)
        if decode:
            data = data.decode('utf-8')
        return data

    def __parse_cookie(self, page: BytesIO, cookie_offset: int):
        page.seek(cookie_offset)
        # cookie size, keep it for future use and better understanding
        _ = struct.unpack('<I', page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        flags = struct.unpack('<I', page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        is_secure = bool(flags & 0x1)
        is_httponly = bool(flags & 0x4)

        host_offset = struct.unpack('<I', page.read(4))[0]
        name_offset = struct.unpack('<I', page.read(4))[0]
        path_offset = struct.unpack('<I', page.read(4))[0]
        value_offset = struct.unpack('<I', page.read(4))[0]
        comment_offset = struct.unpack('<I', page.read(4))[0]

        assert page.read(4) == b'\x00\x00\x00\x00', self.NEW_ISSUE_MESSAGE
        expiry_date = int(struct.unpack('<d', page.read(8))[
                          0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time
        # creation time, keep it for future use and better understanding
        _ = int(struct.unpack('<d', page.read(8))[
            0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time

        page.seek(cookie_offset + host_offset, 0)
        host = self.__read_until_null(page)
        page.seek(cookie_offset + name_offset, 0)
        name = self.__read_until_null(page)
        page.seek(cookie_offset + path_offset, 0)
        path = self.__read_until_null(page)
        page.seek(cookie_offset + value_offset, 0)
        value = self.__read_until_null(page)
        if comment_offset:
            page.seek(cookie_offset + comment_offset, 0)
            # comment, keep it for future use and better understanding
            _ = self.__read_until_null(page)

        return create_cookie(host, path, is_secure, expiry_date, name, value, is_httponly)

    def __domain_filter(self, cookie: http.cookiejar.Cookie):
        if not self.__domain_name:
            return True
        return self.__domain_name in cookie.domain

    def __parse_page(self, page_index: int):
        offset = 8 + self.__total_page * 4 + \
            sum(self.__page_sizes[:page_index])
        page = self.__read_file(self.__page_sizes[page_index], offset)
        assert page.read(4) == b'\x00\x00\x01\x00', self.NEW_ISSUE_MESSAGE
        n_cookies = struct.unpack('<I', page.read(4))[0]
        cookie_offsets = []
        for _ in range(n_cookies):
            cookie_offsets.append(struct.unpack('<I', page.read(4))[0])
        assert page.read(4) == b'\x00\x00\x00\x00', self.NEW_ISSUE_MESSAGE

        for offset in cookie_offsets:
            yield self.__parse_cookie(page, offset)

    def load(self):
        cj = http.cookiejar.CookieJar()
        for i in range(self.__total_page):
            for cookie in self.__parse_page(i):
                if self.__domain_filter(cookie):
                    cj.set_cookie(cookie)
        return cj


def create_cookie(host, path, secure, expires, name, value, http_only):
    """Shortcut function to create a cookie"""
    # HTTPOnly flag goes in _rest, if present (see https://github.com/python/cpython/pull/17471/files#r511187060)
    return http.cookiejar.Cookie(0, name, value, None, False, host, host.startswith('.'), host.startswith('.'), path,
                                 True, secure, expires, False, None, None,
                                 {'HTTPOnly': ''} if http_only else {})


def chrome(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Chrome. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Chrome(cookie_file, domain_name, key_file).load()


def chromium(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Chromium. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Chromium(cookie_file, domain_name, key_file).load()


def opera(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Opera. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Opera(cookie_file, domain_name, key_file).load()


def opera_gx(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Opera GX. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return OperaGX(cookie_file, domain_name, key_file).load()


def brave(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies and sessions used by Brave. Optionally
    pass in a domain name to only load cookies from the specified domain
    """
    return Brave(cookie_file, domain_name, key_file).load()


def edge(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Microsoft Edge. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Edge(cookie_file, domain_name, key_file).load()


def vivaldi(cookie_file=None, domain_name="", key_file=None):
    """Returns a cookiejar of the cookies used by Vivaldi Browser. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Vivaldi(cookie_file, domain_name, key_file).load()


def firefox(cookie_file=None, domain_name=""):
    """Returns a cookiejar of the cookies and sessions used by Firefox. Optionally
    pass in a domain name to only load cookies from the specified domain
    """
    return Firefox(cookie_file, domain_name).load()


def librewolf(cookie_file=None, domain_name=""):
    """Returns a cookiejar of the cookies and sessions used by LibreWolf. Optionally
    pass in a domain name to only load cookies from the specified domain
    """
    return LibreWolf(cookie_file, domain_name).load()


def safari(cookie_file=None, domain_name=""):
    """Returns a cookiejar of the cookies and sessions used by Safari. Optionally
    pass in a domain name to only load cookies from the specified domain
    """
    return Safari(cookie_file, domain_name).load()


def load(domain_name=""):
    """Try to load cookies from all supported browsers and return combined cookiejar
    Optionally pass in a domain name to only load cookies from the specified domain
    """
    cj = http.cookiejar.CookieJar()
    for cookie_fn in [chrome, chromium, opera, opera_gx, brave, edge, vivaldi, firefox, librewolf, safari]:
        try:
            for cookie in cookie_fn(domain_name=domain_name):
                cj.set_cookie(cookie)
        except BrowserCookieError:
            pass
    return cj


if __name__ == '__main__':
    print(load())
