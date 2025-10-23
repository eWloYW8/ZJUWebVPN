# -*- coding: utf-8 -*-
# Author: eWloYW8

__all__ = ["ZJUWebVPNSession", "convert_url", "revert_url", "check_network"]
__version__ = "0.1.3"

import requests
import bs4
import re
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES, PKCS1_v1_5
import binascii
from urllib.parse import urlparse, urlunparse


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


class WengineVPNSession(requests.Session):
    LOGIN_URL = "/login"
    INFO_URL = "/user/info"
    DO_LOGIN_URL = "/do-login"

    def __init__(self, baseURL: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseURL = baseURL.rstrip('/')
        self.logined = False

        index_response = self.get(self.baseURL + self.LOGIN_URL)

        index_parser = bs4.BeautifulSoup(index_response.text, "html.parser")
        self.csrf = index_parser.find("input", {"name": "_csrf"})["value"]
        self.captcha_id = index_parser.find("input", {"name": "captcha_id"})["value"]
    
        password_keyiv_pattern = re.compile(r'encrypt\s*\([^,]+,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
        match = password_keyiv_pattern.search(index_response.text)
        self.password_key = match.group(1)
        self.password_iv = match.group(2)

    def password_encrypt(self, text: str) -> str:
        text_bytes = text.encode('utf-8')
        if len(text_bytes) % 16 != 0:
            text_bytes = pad(text_bytes, 16, style='iso7816')

        key_bytes = self.password_key.encode('utf-8')
        iv_bytes = self.password_iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)
        encrypted = cipher.encrypt(text_bytes)

        result = binascii.hexlify(iv_bytes).decode() + binascii.hexlify(encrypted).decode()[:len(text_bytes) * 2]
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

        print(encrypted_password)

        # login_response = self.post(self.baseURL + self.DO_LOGIN_URL, data=data)
        # login_response_json = login_response.json()

        # if login_response_json.get("code") == 0:
        #     self.logined = True
        # else:
        #     raise Exception("Login failed", login_response_json.get("message", "Unknown error"))


webvpnsession = WengineVPNSession("https://webvpn.zju.edu.cn")






# class ZJUWebVPNSession(requests.Session):
#     """
#     A session class to handle authentication and request routing via ZJU WebVPN.
# 
#     This class automatically logs into the ZJU WebVPN portal upon instantiation,
#     and transparently rewrites outgoing request URLs to pass through the WebVPN.
# 
#     Attributes:
#         LOGIN_AUTH_URL (str): URL to fetch authentication parameters.
#         LOGIN_PSW_URL (str): URL to submit encrypted login credentials.
#         logined (bool): Whether the login has succeeded.
#     """
# 
#     LOGIN_AUTH_URL = "https://webvpn.zju.edu.cn/por/login_auth.csp?apiversion=1"
#     LOGIN_PSW_URL = "https://webvpn.zju.edu.cn/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1"
# 
#     def __init__(self, ZJUWebUser: str, ZJUWebPassword: str, *args, **kwargs):
#         """
#         Initialize a ZJUWebVPNSession instance and log into the WebVPN.
# 
#         Args:
#             ZJUWebUser (str): Your ZJU WebVPN username.
#             ZJUWebPassword (str): Your ZJU WebVPN password.
#             *args, **kwargs: Arguments passed to the base requests.Session class.
# 
#         Raises:
#             Exception: If login fails for any reason (e.g., incorrect credentials).
#         """
#         super().__init__(*args, **kwargs)
#         self.logined = False  # Login status flag
# 
#         # Step 1: Fetch RSA public key and CSRF random code
#         auth_response = self.get(self.LOGIN_AUTH_URL)
#         auth_response_xml = ET.fromstring(auth_response.text)
#         csrfRandCode = auth_response_xml.find("CSRF_RAND_CODE").text
#         encryptKey = auth_response_xml.find("RSA_ENCRYPT_KEY").text
#         encryptExp = auth_response_xml.find("RSA_ENCRYPT_EXP").text
# 
#         # Step 2: Encrypt password and CSRF code using RSA
#         public_key = RSA.construct((int(encryptKey, 16), int(encryptExp)))
#         cipher = PKCS1_v1_5.new(public_key)
#         encrypted = cipher.encrypt(f"{ZJUWebPassword}_{csrfRandCode}".encode())
#         encrypted_hex = binascii.hexlify(encrypted).decode()
# 
#         # Step 3: Submit login request with encrypted credentials
#         data = {
#             "mitm_result": "",                   # Placeholder field (not used here)
#             "svpn_req_randcode": csrfRandCode,    # CSRF random code
#             "svpn_name": ZJUWebUser,              # Username
#             "svpn_password": encrypted_hex,       # Encrypted password + CSRF code
#             "svpn_rand_code": ""                  # Captcha code (empty for now)
#         }
# 
#         login_response = self.post(self.LOGIN_PSW_URL, data=data)
#         login_response_xml = ET.fromstring(login_response.text)
# 
#         # Step 4: Check login result
#         if login_response_xml.find("Result").text == "1":
#             self.logined = True
#         else:
#             # Raise an exception with detailed error message if login fails
#             raise Exception("Login failed", login_response_xml.find("Message").text)
#     
#     def request(self, method, url, *args, webvpn=True, **kwargs):
#         """
#         Override the base request method.
# 
#         If logged into WebVPN, automatically rewrite the URL to pass through WebVPN.
#         Otherwise, behave like a normal requests.Session.
# 
#         Args:
#             method (str): HTTP method (e.g., 'GET', 'POST').
#             url (str): The target URL.
#             webvpn (bool): Whether to request through WebVPN. Default is True.
#             **kwargs: Additional parameters passed to the request.
# 
#         Returns:
#             requests.Response: The response object.
#         """
#         if not self.logined or not webvpn:
#             # If not logged in or webvpn is False, use the original URL
#             return super().request(method, url, *args, **kwargs)
# 
#         # Rewrite URL to pass through WebVPN
#         if isinstance(url, bytes):
#             url = url.decode()
#         new_url = convert_url(url)
#         return super().request(method, new_url, *args, **kwargs)
# 
#     @property
#     def TWFID(self) -> str:
#         """
#         Get the TWFID cookie value from the session.
# 
#         Returns:
#             str: The TWFID cookie value.
#         """
#         return self.cookies.get("TWFID", "")
# 
# 