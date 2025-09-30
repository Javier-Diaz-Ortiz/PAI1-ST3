import socket, json
from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex

HOST = "127.0.0.1"
PORT = 5000

def send(sock, msg):
    sock.send(json.dumps(msg).encode())
    data = sock.recv(4096)
    return json.loads(data.decode())

def register_user(sock, username, password):
    print(f"[+] Registrando usuario {username} ...")
    return send(sock, {"action": "REGISTER", "username": username, "password": password})

def login(sock, username, password):
    resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
    if resp1["status"] != "CHALLENGE":
        return resp1, None

    salt = from_hex(resp1["salt"])
    server_nonce = resp1["server_nonce"]

    verifier = derive_verifier(password, salt)
    client_nonce = gen_nonce_hex(16)
    client_hmac = hmac_sha256(verifier, (client_nonce + server_nonce).encode())

    resp2 = send(sock, {
        "action": "LOGIN_STEP2",
        "username": username,
        "client_nonce": client_nonce,
        "hmac": to_hex(client_hmac)
    })
    return resp2, {"verifier": verifier, "client_nonce": client_nonce, "server_nonce": server_nonce}

def send_transaction(sock, username, session, payload):
    nonce = gen_nonce_hex(8)
    session_key = hmac_sha256(session["verifier"], (session["client_nonce"] + session["server_nonce"]).encode())
    hmac_val = hmac_sha256(session_key, (payload + nonce).encode())

    return send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": payload,
        "nonce": nonce,
        "hmac": to_hex(hmac_val)
    }), {"payload": payload, "nonce": nonce, "hmac": hmac_val}

def replay_transaction(sock, username, tx_data):
    return send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": tx_data["payload"],
        "nonce": tx_data["nonce"],
        "hmac": to_hex(tx_data["hmac"])
    })

def logout(sock, username):
    return send(sock, {"action": "LOGOUT", "username": username})

def brute_force_fail(sock, username):
    # 3 intentos fallidos seguidos
    results = []
    for i in range(3):
        resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
        if resp1.get("status") == "CHALLENGE":
            # Mandar hmac inválido
            resp2 = send(sock, {
                "action": "LOGIN_STEP2",
                "username": username,
                "client_nonce": gen_nonce_hex(16),
                "hmac": "deadbeef"
            })
            results.append(resp2)
    return results

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        print(register_user(s, "javi", "password123"))
        resp, session = login(s, "javi", "password123")
        print(resp)

        if resp["status"] == "LOGIN_OK":
            tx_resp, tx_data = send_transaction(s, "javi", session, "Cuenta1,Cuenta2,100.0")
            print(tx_resp)
            print(replay_transaction(s, "javi", tx_data))
            print(logout(s, "javi"))

        # Usuario inexistente
        print(login(s, "bob", "wrongpass"))

        # Intentos fallidos para bloquear
        print(brute_force_fail(s, "alice"))
