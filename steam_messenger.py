from typing import Union, Dict, Optional
from requests import Session, Response
from Crypto.Cipher import PKCS1_v1_5
from websocket import WebSocketApp
from Crypto.PublicKey import RSA
from struct import pack, unpack
from secrets import token_hex
from base64 import b64encode
from json import load, loads
from time import time, sleep
from threading import Thread
from html import unescape
from re import search

import steam_session
import protobuf

class SteamMessenger:
    SERVICE_METHOD_RESPONSE: int = 152
    SERVICE_METHOD: int = 151
    CLIENT_HELLO: int = 5514
    SERVER_HELLO: int = 1
    ACK: int = 9802
    
    def __init__(self, session: Session, headers: dict, username: str) -> None:
        self.session = session
        self.headers = headers
        self.username = username

        self.authenticated: bool = False
        self.running: bool = False
        self.job_id: int = 1
        self.ws = None
        
        self.chat_token: Optional[str] = self.get_chat_token()
        self.cm_info: dict = self.get_cm_servers()
        self.proto = protobuf.Protobuf()
    
    def get_chat_token(self) -> Optional[str]:
        try:
            response: Session = self.session.get("https://steamcommunity.com/chat/", headers=self.headers)

            if response.status_code == 200:
                match = search(r'data-userinfo="([^"]+)"', response.text)

                if match:
                    userinfo_json: str = unescape(match.group(1))
                    userinfo: dict = loads(userinfo_json)
                    token: Optional[str] = userinfo.get("token")

                    if token:
                        return token

        except:
            pass
        
        return None
    
    def get_cm_servers(self) -> dict:
        try:
            response: Session = self.session.get("https://steamcommunity.com/chat/clientjstoken", headers=self.headers)
            if response.status_code == 200:
                return response.json()

        except:
            pass

        return {}
    
    def create_message(self, msg_id: int, payload: bytes, session_id: int = 9) -> bytes:
        msg_id_with_flag: int = msg_id | 0x80000000
        header: bytes = pack("<I", msg_id_with_flag)
        header += pack("<I", session_id)
        return header + payload
    
    def create_client_hello(self) -> bytes:
        self.proto.reset()
        self.proto.encode_fixed64(1, 0x0110000170560549)
        self.proto.encode_int(1, 65580)
        self.proto.encode_int(7, 4294966596)
        self.proto.encode_int(21, 2)
        self.proto.encode_int(32, 3)
        self.proto.encode_int(33, 2)
        self.proto.encode_bytes(50, self.username)
        self.proto.encode_int(100, 0)
        
        if self.chat_token:
            self.proto.encode_bytes(103, self.chat_token)
        
        payload: bytes = self.proto.get_bytes()
        return self.create_message(self.CLIENT_HELLO, payload, session_id=9)
    
    def create_heartbeat(self) -> bytes:
        self.proto.reset()
        self.proto.encode_fixed64(1, 0x0110000170560549)
        self.proto.encode_int(2, -1)
        self.proto.encode_fixed64(10, self.job_id)
        self.proto.encode_bytes(12, "Player.GetCommunityPreferences#1")
        
        self.job_id += 1
        payload: bytes = self.proto.get_bytes()
        return self.create_message(self.SERVICE_METHOD, payload, session_id=59)
    
    def send_friend_message(self, recipient_steamid: str, message_text: str) -> None:
        timeout: int = 10
        while not self.authenticated and timeout > 0:
            sleep(0.5)
            timeout -= 0.5
        
        if not self.authenticated:
            return
        
        recipient_steamid_int = int(recipient_steamid)
        recipient_accountid: int = recipient_steamid_int - 76561197960265728
        recipient_encoded: int = 0x0110000170000000 | recipient_accountid
        
        inner_proto = protobuf.Protobuf()
        inner_proto.encode_fixed64(1, recipient_encoded)
        inner_proto.encode_int(2, 1)
        inner_proto.encode_bytes(3, message_text)
        inner_proto.encode_int(4, 1)
        inner_proto.encode_bytes(8, token_hex(8))
        
        self.proto.reset()
        self.proto.encode_fixed64(1, 0x0110000170560549)
        self.proto.encode_int(2, -1)
        self.proto.encode_fixed64(10, self.job_id)
        self.proto.encode_bytes(12, "FriendMessages.SendMessage#1")
        self.proto.buffer.extend(inner_proto.get_bytes())
        
        self.job_id += 1
        payload: bytes = self.proto.get_bytes()
        message: bytes = self.create_message(self.SERVICE_METHOD, payload, session_id=59)
        
        try:
            self.ws.send(message, opcode=2)
            print(f"[>] Sent: '{message_text}'")

        except:
            pass
    
    def on_message(self, ws: WebSocketApp, message: bytes) -> None:
        if len(message) >= 8:
            msg_id: int = unpack("<I", message[0:4])[0] & 0x7FFFFFFF
            if msg_id == self.SERVER_HELLO:
                self.authenticated = True
    
    def on_open(self, ws: WebSocketApp) -> None:
        client_hello: bytes = self.create_client_hello()
        ws.send(client_hello, opcode=2)
    
    def on_close(self, ws: WebSocketApp, close_status_code: int, close_msg: str) -> None:
        self.running: bool = False
    
    def on_error(self, ws: WebSocketApp, error: Exception) -> None:
        print(f"[!] Error: {error}")
    
    def heartbeat_loop(self) -> None:
        while self.running:
            sleep(30)
            if self.running and self.ws and self.authenticated:
                try:
                    heartbeat: bytes = self.create_heartbeat()
                    self.ws.send(heartbeat, opcode=2)

                except:
                    pass
    
    def connect(self) -> None:
        header: list = [
            "Origin: https://steamcommunity.com",
            f"User-Agent: {self.headers.get('user-agent', 'Mozilla/5.0')}",
            f"Cookie: {'; '.join([f'{c.name}={c.value}' for c in self.session.cookies])}"
        ]

        self.ws = WebSocketApp(
            "wss://cmp2-ord1.steamserver.net:27018/cmsocket/",
            header=header,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        
        self.running: bool = True
        Thread(target=self.heartbeat_loop, daemon=True).start()
        self.ws.run_forever()

def run_script() -> None:
    auth = steam_session.SteamSession()
    client = SteamMessenger(
        session=auth.session,
        headers=auth.headers,
        username=auth.username
    )
    
    ws_thread = Thread(target=client.connect, daemon=True)
    ws_thread.start()
    
    sleep(1.5)

    # Send messages at .75 second interval to prevent rate limiting
    recipient_id: str = input("Enter recipient SteamID64: ")
    for x in range(5):
        client.send_friend_message(recipient_id, f"Message {x}")
        sleep(0.75)

if __name__ == "__main__":
    run_script()