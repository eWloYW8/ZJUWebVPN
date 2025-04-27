import requests
import xml.etree.ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import binascii
from urllib.parse import urlparse, urlunparse

class ZJUWebVPNSession(requests.Session):

    LOGIN_AUTH_URL = "https://webvpn.zju.edu.cn/por/login_auth.csp?apiversion=1"
    LOGIN_PSW_URL = "https://webvpn.zju.edu.cn/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1"

    def __init__(self, ZJUWebUser, ZJUWebPassword, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logined = False

        auth_response = self.get(self.LOGIN_AUTH_URL)
        auth_response_xml = ET.fromstring(auth_response.text)
        csrfRandCode = auth_response_xml.find("CSRF_RAND_CODE").text
        encryptKey = auth_response_xml.find("RSA_ENCRYPT_KEY").text
        encryptExp = auth_response_xml.find("RSA_ENCRYPT_EXP").text

        public_key = RSA.construct((int(encryptKey, 16), int(encryptExp)))
        cipher = PKCS1_v1_5.new(public_key)
        encrypted = cipher.encrypt(f"{ZJUWebPassword}_{csrfRandCode}".encode())
        encrypted_hex = binascii.hexlify(encrypted).decode()

        data = {
            "mitm_result": "",
            "svpn_req_randcode": csrfRandCode,
            "svpn_name": ZJUWebUser,
            "svpn_password": encrypted_hex,
            "svpn_rand_code": ""
        }

        login_response = self.post(self.LOGIN_PSW_URL, data=data)
        login_response_xml = ET.fromstring(login_response.text)

        if login_response_xml.find("Result").text == "1":
            self.logined = True
        else:
            raise Exception("Login failed", login_response_xml.find("Message").text)
    
    @staticmethod
    def convert_url(original_url):
        parsed = urlparse(original_url)
    
        hostname = parsed.hostname.replace('.', '-')

        if parsed.scheme == 'https':
            hostname += '-s'

        if parsed.port and not (parsed.scheme == 'http' and parsed.port == 80) and not (parsed.scheme == 'https' and parsed.port == 443):
            hostname += f'-{parsed.port}-p'

        hostname += '.webvpn.zju.edu.cn:8001'

        new_url = urlunparse(('http', hostname, parsed.path or '/', '', '', ''))

        return new_url
    
    def request(self, method, url, **kwargs):
        if not self.logined:
            return super().request(method, url, **kwargs)

        new_url = self.convert_url(url)
        return super().request(method, new_url, **kwargs)

