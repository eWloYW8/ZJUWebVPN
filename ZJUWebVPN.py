# -*- coding: utf-8 -*-
# Author: eWloYW8

__all__ = ["ZJUWebVPNSession", "WengineVPNSession"]
__version__ = "0.2.1"

import requests
import bs4
import re
from Crypto.Cipher import AES
import binascii
from urllib.parse import urlparse, urlunparse

class WengineVPNSession(requests.Session):
    LOGIN_URL = "/login"
    INFO_URL = "/user/info"
    DO_LOGIN_URL = "/do-login"

    def __init__(self, baseURL: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseURL = baseURL.rstrip('/')
        self.logined = False

        index_response = self.get(self.baseURL + self.LOGIN_URL, webvpn=False)

        index_parser = bs4.BeautifulSoup(index_response.text, "html.parser")
        self.csrf = index_parser.find("input", {"name": "_csrf"})["value"]
        self.captcha_id = index_parser.find("input", {"name": "captcha_id"})["value"]
    
        password_keyiv_pattern = re.compile(r'encrypt\s*\([^,]+,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
        match = password_keyiv_pattern.search(index_response.text)
        self.password_key = match.group(1)
        self.password_iv = match.group(2)

    def password_encrypt(self, text: str) -> str:
        text_bytes = text.encode('utf-8')

        key_bytes = self.password_key.encode('utf-8')
        iv_bytes = self.password_iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)
        encrypted = cipher.encrypt(text_bytes)
    
        result = (
            binascii.hexlify(iv_bytes).decode()
            + binascii.hexlify(encrypted).decode()
        )
        return result

    def login(self, username: str, password: str):
        encrypted_password = self.password_encrypt(password)

        data = {
            "_csrf": self.csrf,
            "auth_type": "local",
            "username": username,
            "sms_code": "",
            "password": encrypted_password,
            "captcha": "",
            "needCaptcha": "false",
            "captcha_id": self.captcha_id,
        }

        login_response = self.post(self.baseURL + self.DO_LOGIN_URL, data=data, webvpn=False)
        login_response_json = login_response.json()

        if not login_response_json.get("error"):
            userinfo_response = self.get(self.baseURL + self.INFO_URL, webvpn=False)
            userinfo_response_json = userinfo_response.json()

            self.URL_encrypt_iv = userinfo_response_json["wrdvpnIV"]
            self.URL_encrypt_key = userinfo_response_json["wrdvpnKey"]
            self.canVisitProtocol = userinfo_response_json["canVisitProtocol"]

            
            self.logined = True
        else:
            raise Exception("Login failed", login_response_json.get("message", "Unknown error"))

    def convert_url(self, url: str) -> str:
        if not self.logined:
            raise Exception("Not logged in")
        
        urlparse_result = urlparse(url)
        scheme = urlparse_result.scheme.lower()
        hostname = urlparse_result.hostname
        port = urlparse_result.port
        path = urlparse_result.path
        query = urlparse_result.query

        if port:
            scheme += f"-{port}"

        key_bytes = self.URL_encrypt_key.encode('utf-8')
        iv_bytes = self.URL_encrypt_iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)
        hostname_bytes = hostname.encode('utf-8')

        encrypted = cipher.encrypt(hostname_bytes)

        encrypted_hex = (
            binascii.hexlify(iv_bytes).decode()
            + binascii.hexlify(encrypted).decode()
        )
        converted_url = f"{self.baseURL}/{scheme}/{encrypted_hex}{path}{'?' if query else ''}{query}"

        return converted_url

    def revert_url(self, webvpn_url: str) -> str:
        if not self.logined:
            raise Exception("Not logged in")

        urlparse_result = urlparse(webvpn_url)
        path = urlparse_result.path.lstrip('/')
        query = urlparse_result.query

        path_parts = path.split('/', 2)
        if len(path_parts) < 2:
            raise ValueError("Invalid WebVPN URL format")

        scheme_port = path_parts[0]
        encrypted_hex = path_parts[1]
        original_path = '/' + path_parts[2] if len(path_parts) > 2 else ''

        if '-' in scheme_port:
            scheme, port_str = scheme_port.split('-', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
        else:
            scheme = scheme_port
            port = None

        iv_hex = encrypted_hex[:32]
        encrypted_hostname_hex = encrypted_hex[32:]

        iv_bytes = binascii.unhexlify(iv_hex)
        encrypted_hostname_bytes = binascii.unhexlify(encrypted_hostname_hex)
        key_bytes = self.URL_encrypt_key.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)
        decrypted_hostname_bytes = cipher.decrypt(encrypted_hostname_bytes)

        hostname = decrypted_hostname_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')

        if port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        original_url = urlunparse((
            scheme,
            netloc,
            original_path,
            '',
            query,
            ''
        ))

        return original_url


    def request(self, method, url, *args, webvpn=True, **kwargs):
        if not self.logined:
            if webvpn:
                print("WebVPN Warning: Not logged in, cannot use WebVPN routing.")
            return super().request(method, url, *args, **kwargs)

        if isinstance(url, bytes):
            url = url.decode()
        new_url = self.convert_url(url)
        return super().request(method, new_url, *args, **kwargs)


class ZJUWebVPNSession(WengineVPNSession):
    ZJU_WEBVPN_BASEURL = "https://webvpn.zju.edu.cn"

    def __init__(self, username=None, password=None, *args, **kwargs):
        super().__init__(self.ZJU_WEBVPN_BASEURL, *args, **kwargs)
        if username and password:
            self.login(username, password)

    @staticmethod
    def check_network() -> int:
        """
        Check the network environment by using the Zhejiang University Mirror API.

        This function queries the Zhejiang University Mirror API to determine the
        current network environment. It checks if the network is within the campus network
        and whether it is using IPv4 or IPv6.

        Returns:
            int: The network status.  
                - 0: Not in the campus network.  
                - 1: Campus network with IPv4.  
                - 2: Campus network with IPv6.  
        """
        network_check_api_url = "https://mirrors.zju.edu.cn/api/is_campus_network"
        response = requests.get(network_check_api_url)
        return int(response.text)

    @property
    def wengine_vpn_ticket(self) -> str:
        return self.cookies.get("wengine_vpn_ticketwebvpn_zju_edu_cn", "")
