# -*- coding: utf-8 -*-
# Author: eWloYW8

__all__ = ["ZJUWebVPNSession"]

import requests
import xml.etree.ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import binascii
from urllib.parse import urlparse, urlunparse

class ZJUWebVPNSession(requests.Session):
    """
    A session class to handle authentication and request routing via ZJU WebVPN.

    This class automatically logs into the ZJU WebVPN portal upon instantiation,
    and transparently rewrites outgoing request URLs to pass through the WebVPN.

    Attributes:
        LOGIN_AUTH_URL (str): URL to fetch authentication parameters.
        LOGIN_PSW_URL (str): URL to submit encrypted login credentials.
        logined (bool): Whether the login has succeeded.
    """

    LOGIN_AUTH_URL = "https://webvpn.zju.edu.cn/por/login_auth.csp?apiversion=1"
    LOGIN_PSW_URL = "https://webvpn.zju.edu.cn/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1"

    def __init__(self, ZJUWebUser, ZJUWebPassword, *args, **kwargs):
        """
        Initialize a ZJUWebVPNSession instance and log into the WebVPN.

        Args:
            ZJUWebUser (str): Your ZJU WebVPN username.
            ZJUWebPassword (str): Your ZJU WebVPN password.
            *args, **kwargs: Arguments passed to the base requests.Session class.

        Raises:
            Exception: If login fails for any reason (e.g., incorrect credentials).
        """
        super().__init__(*args, **kwargs)
        self.logined = False  # Login status flag

        # Step 1: Fetch RSA public key and CSRF random code
        auth_response = self.get(self.LOGIN_AUTH_URL)
        auth_response_xml = ET.fromstring(auth_response.text)
        csrfRandCode = auth_response_xml.find("CSRF_RAND_CODE").text
        encryptKey = auth_response_xml.find("RSA_ENCRYPT_KEY").text
        encryptExp = auth_response_xml.find("RSA_ENCRYPT_EXP").text

        # Step 2: Encrypt password and CSRF code using RSA
        public_key = RSA.construct((int(encryptKey, 16), int(encryptExp)))
        cipher = PKCS1_v1_5.new(public_key)
        encrypted = cipher.encrypt(f"{ZJUWebPassword}_{csrfRandCode}".encode())
        encrypted_hex = binascii.hexlify(encrypted).decode()

        # Step 3: Submit login request with encrypted credentials
        data = {
            "mitm_result": "",                   # Placeholder field (not used here)
            "svpn_req_randcode": csrfRandCode,    # CSRF random code
            "svpn_name": ZJUWebUser,              # Username
            "svpn_password": encrypted_hex,       # Encrypted password + CSRF code
            "svpn_rand_code": ""                  # Captcha code (empty for now)
        }

        login_response = self.post(self.LOGIN_PSW_URL, data=data)
        login_response_xml = ET.fromstring(login_response.text)

        # Step 4: Check login result
        if login_response_xml.find("Result").text == "1":
            self.logined = True
        else:
            # Raise an exception with detailed error message if login fails
            raise Exception("Login failed", login_response_xml.find("Message").text)
    
    @staticmethod
    def convert_url(original_url):
        """
        Convert an original URL to the format required by WebVPN.

        WebVPN rewrites hostnames by replacing dots with hyphens,
        appending '-s' for HTTPS, and including port information if needed.

        Args:
            original_url (str): The original URL to access.

        Returns:
            str: The rewritten URL for WebVPN.
        """
        parsed = urlparse(original_url)
    
        # Rewrite hostname: replace '.' with '-'
        hostname = parsed.hostname.replace('.', '-')

        # Append '-s' if the original scheme is HTTPS
        if parsed.scheme == 'https':
            hostname += '-s'

        # Append port information if not standard ports
        if parsed.port and not (parsed.scheme == 'http' and parsed.port == 80) and not (parsed.scheme == 'https' and parsed.port == 443):
            hostname += f'-{parsed.port}-p'

        # Add WebVPN domain suffix
        hostname += '.webvpn.zju.edu.cn:8001'

        # Assemble final URL
        new_url = urlunparse(('http', hostname, parsed.path or '/', '', '', ''))

        return new_url
    
    def request(self, method, url, **kwargs):
        """
        Override the base request method.

        If logged into WebVPN, automatically rewrite the URL to pass through WebVPN.
        Otherwise, behave like a normal requests.Session.

        Args:
            method (str): HTTP method (e.g., 'GET', 'POST').
            url (str): The target URL.
            **kwargs: Additional parameters passed to the request.

        Returns:
            requests.Response: The response object.
        """
        if not self.logined:
            # Not logged in, normal behavior
            return super().request(method, url, **kwargs)

        # Rewrite URL to pass through WebVPN
        new_url = self.convert_url(url)
        return super().request(method, new_url, **kwargs)

