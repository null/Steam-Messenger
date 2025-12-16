from requests import Session, Response
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from typing import Union, Dict
from base64 import b64encode
from json import load
from time import time

import protobuf

class SteamSession:
    def __init__(self) -> None:
        with open("config.json") as cfg:
            config: dict = load(cfg)

        self.username: str = config["steam_login_information"]["username"]
        self.password: str = config["steam_login_information"]["password"]
        self.session: Session = Session()
        self.headers: dict = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "origin": "https://steamcommunity.com"
        }

        self.boundary: str = f"WebKitFormBoundary{b64encode(str(int(time())).encode()).decode()[:16]}"
        self.transfer_info: list = []
        self.proto = protobuf.Protobuf()
        
        self.encrypted_password = None
        self.rsa_timestamp = None
        self.refresh_token = None
        self.request_id = None
        self.client_id = None
        self.jwt_token = None
        self.steam_id = None
        self.rsa_key = None

        self.steam_session: Session = self.login()

    def encrypt_password(self) -> str:
        rsa_list = self.rsa_key.split('|')
        mod = int(rsa_list[0], 16)
        exp = int(rsa_list[1], 16) if len(rsa_list) == 2 else 65537
        
        key = RSA.construct((mod, exp))
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(self.password.encode("utf-8"))
        return b64encode(encrypted).decode("utf-8")

    def encode_username(self) -> str:
        self.proto.reset()
        self.proto.encode_bytes(1, self.username)
        return b64encode(self.proto.get_bytes()).decode("utf-8")

    def encode_login_request(self) -> str:
        self.proto.reset()
        self.proto.encode_bytes(1, self.headers["user-agent"])
        self.proto.encode_int(2, 2)
        encoded_device = self.proto.get_bytes()
        
        self.proto.reset()
        for field, value in [(2, self.username), (3, self.encrypted_password), (8, "Community"), (9, encoded_device)]:
            self.proto.encode_bytes(field, value) if isinstance(value, (str, bytes)) else self.proto.encode_message(field, value)
        
        for field, value in [(4, self.rsa_timestamp), (5, 1), (7, 1), (11, 2), (12, 0)]:
            self.proto.encode_int(field, value)
        
        return b64encode(self.proto.get_bytes()).decode("utf-8")

    def encode_poll_request(self) -> str:
        self.proto.reset()
        self.proto.encode_int(1, self.client_id)
        self.proto.encode_bytes(2, self.request_id)
        return b64encode(self.proto.get_bytes()).decode("utf-8")

    def encode_steamguard_code_request(self, code: str) -> str:
        self.proto.reset()
        self.proto.encode_int(1, self.client_id)
        self.proto.encode_fixed64(2, self.steam_id)  
        self.proto.encode_bytes(3, code)
        self.proto.encode_int(4, 2)
        return b64encode(self.proto.get_bytes()).decode("utf-8")
    
    def multipart_body(self, *fields) -> str:
        parts: list = [f'------{self.boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}' 
                 for k, v in fields]
        return f'{chr(10).join(parts)}\r\n------{self.boundary}--\r\n'
    
    def multipart_post(self, url: str, body: str, extra_headers=None) -> Response:
        headers: dict = self.headers.copy()
        headers["content-type"] = f"multipart/form-data; boundary=----{self.boundary}"

        if extra_headers:
            headers.update(extra_headers)

        return self.session.post(url, data=body.encode("utf-8"), headers=headers)
    
    def get_rsa_key(self) -> bool:
        try:
            response: Response = self.session.get(
                "https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1",
                params={"input_protobuf_encoded": self.encode_username(), "origin": "https://steamcommunity.com"},
                headers=self.headers
            )
            
            if response.status_code == 200:
                self.proto.load_data(response.content)
                fields = self.proto.decode_message()
                if 1 not in fields:
                    raise Exception()
                
                modulus = fields[1].decode("utf-8") if isinstance(fields[1], bytes) else fields[1]
                exp_val = fields.get(2, 65537)
                exponent = exp_val.decode("utf-8") if isinstance(exp_val, bytes) else hex(exp_val)[2:]
                
                self.rsa_key: str = f"{modulus}|{exponent}"
                self.rsa_timestamp = fields.get(3, int(time() * 1000))
                return True

            else:
                raise Exception()

        except:
            pass

        return False
    
    def begin_auth_session(self) -> bool:
        try:
            self.encrypted_password = self.encrypt_password()

            body: str = self.multipart_body(("input_protobuf_encoded", self.encode_login_request()))
            response: Response = self.multipart_post(
                "https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1", body
            )
            
            if response.status_code == 200:
                self.proto.load_data(response.content)
                fields = self.proto.decode_message()
                self.request_id: str = fields.get(2)
                if not self.request_id:
                    raise Exception()
                
                self.client_id: str = fields.get(1)
                self.steam_id: Optional[str] = str(fields[5]) if 5 in fields else None
                self.jwt_token: Optional[str] = fields[6].decode("utf-8") if 6 in fields and isinstance(fields[6], bytes) else None
                return True

            else:
                raise Exception()

        except:
            pass

        return False
    
    def check_device(self) -> bool:
        try:

            body: str = self.multipart_body(("clientid", self.client_id), ("steamid", self.steam_id))
            response: Response = self.multipart_post(f"https://login.steampowered.com/jwt/checkdevice/{self.steam_id}", body)
            if response.status_code == 200:
                return True

            else:
                raise Exception()

        except:
            pass

        return False
    
    def submit_email_code(self, code: str) -> bool:
        try:
            body: str = self.multipart_body(("input_protobuf_encoded", self.encode_steamguard_code_request(code)))
            response: Response = self.multipart_post(
                "https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1", body
            )

            if response.status_code == 200:
                return True

            else:
                raise Exception()

        except:
            pass

        return False
    
    def poll_auth_session(self) -> bool:
        try:
            body: str = self.multipart_body(("input_protobuf_encoded", self.encode_poll_request()))
            response: Response = self.multipart_post(
                "https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1", body
            )
            
            if response.status_code == 200:
                self.proto.load_data(response.content)
                fields: Dict[int, Union[int, bytes]] = self.proto.decode_message()
                for field_num in [1, 3, 4]:
                    if field_num in fields and isinstance(fields[field_num], bytes) and len(fields[field_num]) > 100:
                        self.refresh_token = fields[field_num].decode("utf-8")
                        return True

            else:
                raise Exception()

        except:
            pass

        return False
    
    def finalize_login(self) -> bool:
        try:
            body: str = self.multipart_body(
                ("nonce", self.refresh_token),
                ("sessionid", self.session.cookies.get("sessionid", "")),
                ("redir", "https://steamcommunity.com/login/home/?goto=")
            )
            
            response: Response = self.multipart_post(
                "https://login.steampowered.com/jwt/finalizelogin", body,
                {"referer": "https://steamcommunity.com/login/home/?goto="}
            )
            
            if response.status_code == 200:
                self.transfer_info: str = response.json()["transfer_info"]
                return True

            else:
                raise Exception()

        except:
            pass

        return False

    def set_tokens(self) -> bool:
        try:
            for transfer in self.transfer_info:
                domain_url: str = transfer.get("url")
                params = transfer.get("params", {})
                
                body: str = self.multipart_body(
                    ("nonce", params.get("nonce", "")),
                    ("auth", params.get("auth", "")),
                    ("steamID", self.steam_id)
                )
                
                is_community: bool = "steamcommunity.com" in domain_url
                extra_headers: dict = {
                    "referer": "https://steamcommunity.com/login/home/?goto=",
                    "sec-fetch-site": "same-origin"
                }
                self.multipart_post(domain_url, body, extra_headers)
            
            print(f"Steam ID: {self.steam_id}")
            return self.session

        except:
            pass

        return False

    def login(self) -> Session:
        self.get_rsa_key()
        self.begin_auth_session()
        self.check_device()
        self.submit_email_code(input("[?] Enter OTP Code: "))
        self.poll_auth_session()
        self.finalize_login()

        self.set_tokens()