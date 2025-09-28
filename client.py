# client.py
import socket, json, binascii
from crypto_utils import generate_salt, derive_verifier, hmac_sha256, gen_nonce_hex, to_hex, from_hex
import getpass

HOST = '127.0.0.1'
PORT = 5000

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())

def recv_json(conn):
    buffer = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer += chunk
        if b"\n" in buffer:
            line, rest = buffer.split(b"\n",1)
            return json.loads(line.decode())

def register(conn, username, password):
    send_json(conn, {'type':'REGISTER','username':username,'password':password})
    return recv_json(conn)

def login(conn, username, password):
    # step 1: request challenge
    send_json(conn, {'type':'LOGIN_STEP1','username': username})
    resp = recv_json(conn)
    if resp['type'] != 'LOGIN_CHALLENGE':
        return resp
    salt_hex = resp['salt']
    server_nonce = resp['server_nonce']
    # derive verifier locally
    salt = from_hex(salt_hex)
    verifier = derive_verifier(password, salt)
    # respond with HMAC(verifier, server_nonce)
    response_hmac = hmac_sha256(verifier, server_nonce.encode())
    client_nonce = gen_nonce_hex(16)
    send_json(conn, {'type':'LOGIN_STEP2','username': username,
                     'response_hmac': to_hex(response_hmac),
                     'client_nonce': client_nonce})
    resp2 = recv_json(conn)
    if resp2['type'] == 'LOGIN_OK':
        # both sides can compute session_key now the same way:
        session_key = hmac_sha256(verifier, server_nonce.encode() + client_nonce.encode())
        return {'status':'OK','session_key': to_hex(session_key)}
    else:
        return resp2

def send_transaction(conn, username, session_key_hex, payload):
    nonce = gen_nonce_hex(16)
    session_key = from_hex(session_key_hex)
    hmac_val = hmac_sha256(session_key, (payload + nonce).encode())
    send_json(conn, {'type':'TRANSACTION','username':username,
                     'payload': payload, 'nonce':nonce, 'hmac': to_hex(hmac_val)})
    return recv_json(conn)

# Ejemplo uso:
if __name__ == "__main__":
    s = socket.create_connection((HOST, PORT))
    username = input("username: ")
    pw = getpass.getpass("password: ")
    # descomenta para registrar si hace falta:
    # print(register(s, username, pw))
    login_res = login(s, username, pw)
    print("Login result:", login_res)
    if login_res.get('status') == 'OK':
        sk = login_res['session_key']
        payload = input("Introduce transacción (origen,destino,cantidad): ")
        print(send_transaction(s, username, sk, payload))
    s.close()
