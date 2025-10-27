from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')


def serialize_key(key_obj):
    return key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def deserialize_key(pem_str):
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None
    )

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        print("Generating and inserting initial keys...")

        
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        valid_pem = serialize_key(valid_key)
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, valid_exp))

        
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
        expired_pem = serialize_key(expired_key)
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, expired_exp))

        conn.commit()

    conn.close()

def get_key_from_db(expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(datetime.datetime.utcnow().timestamp())

    if expired:
        cursor.execute("SELECT key, exp FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1", (now,))
    else:
        cursor.execute("SELECT key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))

    row = cursor.fetchone()
    conn.close()
    if row:
        return deserialize_key(row[0]), row[1]
    return None, None


def get_valid_keys_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute("SELECT key, exp FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()
    return [deserialize_key(r[0]) for r in rows]

class MyServer(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json.dumps(data), "utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/auth":
            expired_flag = 'expired' in params
            key_obj, exp_ts = get_key_from_db(expired=expired_flag)

            if not key_obj:
                self._send_json(404, {"error": "No key found"})
                return

            headers = {"kid": "expiredKID" if expired_flag else "goodKID"}
            token_payload = {
                "user": "username",
                "exp": exp_ts
            }

            pem = serialize_key(key_obj)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self._send_json(200, {"token": encoded_jwt})
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys = []
            valid_keys = get_valid_keys_from_db()
            for key_obj in valid_keys:
                public_numbers = key_obj.public_key().public_numbers()
                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e)
                })
            self._send_json(200, {"keys": keys})
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        print("Initializing new key database...")
    init_db()
    print(f"Starting JWKS server at http://{hostName}:{serverPort}")
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()