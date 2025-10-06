# test_client_extended.py
import socket, json, time, statistics
from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex

HOST = "127.0.0.1"
PORT = 5000

def send(sock, msg):
    sock.send(json.dumps(msg).encode())
    data = sock.recv(8192)
    if not data:
        return None
    return json.loads(data.decode())

def register_user(sock, username, password):
    print(f"[+] Registrando usuario {username} ...")
    return send(sock, {"action": "REGISTER", "username": username, "password": password})

def login(sock, username, password):
    resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
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

    resp = send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": payload,
        "nonce": nonce,
        "hmac": to_hex(hmac_val)
    })
    return resp, {"payload": payload, "nonce": nonce, "hmac": hmac_val}

def replay_transaction(sock, username, tx_data):
    return send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": tx_data["payload"],
        "nonce": tx_data["nonce"],
        "hmac": to_hex(tx_data["hmac"])
    })

def mitm_modify_payload(sock, username, tx_data, new_payload):
    """
    Attacker modifies payload but uses a NEW nonce (so server won't treat as replay)
    and reuses old HMAC (attacker cannot recompute HMAC for new payload+nonce).
    Expect: integrity_error
    """
    nonce_new = gen_nonce_hex(8)
    return send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": new_payload,
        "nonce": nonce_new,
        "hmac": to_hex(tx_data["hmac"])
    })

def mitm_modify_hmac(sock, username, tx_data):
    """
    Attacker sends a NEW nonce and a bogus HMAC (corrupted).
    Expect: integrity_error
    """
    nonce_new = gen_nonce_hex(8)
    fake_hmac_hex = to_hex(b"\x00" * 32)
    return send(sock, {
        "action": "TRANSACTION",
        "username": username,
        "payload": tx_data["payload"],
        "nonce": nonce_new,
        "hmac": fake_hmac_hex
    })

def brute_force_fail(sock, username):
    results = []
    for i in range(3):
        resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
        if resp1 and resp1.get("status") == "CHALLENGE":
            resp2 = send(sock, {
                "action": "LOGIN_STEP2",
                "username": username,
                "client_nonce": gen_nonce_hex(16),
                "hmac": "deadbeef"
            })
            results.append(resp2)
    return results

def timing_test_transaction(sock, username, session, payload, n=20):
    """
    Measure round-trip times for correct vs incorrect HMAC to check for timing side-channels.
    After server change storing async, OK vs BAD should be similar.
    """
    times_ok = []
    times_bad = []
    for i in range(n):
        # correct
        nonce = gen_nonce_hex(8)
        session_key = hmac_sha256(session["verifier"], (session["client_nonce"] + session["server_nonce"]).encode())
        hmac_ok = hmac_sha256(session_key, (payload + nonce).encode())
        msg_ok = {
            "action": "TRANSACTION", "username": username,
            "payload": payload, "nonce": nonce, "hmac": to_hex(hmac_ok)
        }
        t0 = time.perf_counter()
        send(sock, msg_ok)
        t1 = time.perf_counter()
        times_ok.append(t1 - t0)

        # incorrect (corrupt HMAC)
        nonce2 = gen_nonce_hex(8)
        hmac_bad = b"\x00" * 32
        msg_bad = {
            "action": "TRANSACTION", "username": username,
            "payload": payload, "nonce": nonce2, "hmac": to_hex(hmac_bad)
        }
        t0 = time.perf_counter()
        send(sock, msg_bad)
        t1 = time.perf_counter()
        times_bad.append(t1 - t0)

    return {"ok": times_ok, "bad": times_bad}

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        print("=== REGISTER ===")
        print(register_user(s, "javi", "password123"))

        print("\n=== LOGIN ===")
        resp, session = login(s, "javi", "password123")
        print("Login response:", resp)

        if resp and resp.get("status") == "LOGIN_OK":
            print("\n--- Transacción válida ---")
            tx_resp, tx_data = send_transaction(s, "javi", session, "Cuenta1,Cuenta2,100.0")
            print("Valid TX response:", tx_resp)

            print("\n--- Replay (misma nonce/hmac) ---")
            replay_resp = replay_transaction(s, "javi", tx_data)
            print("Replay response (expected: error/replay_detected):", replay_resp)

            print("\n--- MITM: change payload but reuse old HMAC (should fail by integrity) ---")
            mitm1 = mitm_modify_payload(s, "javi", tx_data, "Cuenta1,Cuenta2,1000000.0")
            print("MITM payload-change response (expected: integrity error):", mitm1)

            print("\n--- MITM: corrupt HMAC (should fail) ---")
            mitm2 = mitm_modify_hmac(s, "javi", tx_data)
            print("MITM corrupt-hmac response (expected: integrity error):", mitm2)

            print("\n--- LOGOUT ---")
            print(send(s, {"action":"LOGOUT","username":"javi"}))

        print("\n=== Login invalid / brute force ===")
        print(login(s, "nonexistent_user", "whatever"))
        print("Brute-force attempts (alice):", brute_force_fail(s, "alice"))

        print("\n=== Timing test ===")
        # Start a fresh login to get a new session for timing test
        resp_t, session_t = login(s, "javi", "password123")
        if resp_t and resp_t.get("status") == "LOGIN_OK":
            times = timing_test_transaction(s, "javi", session_t, "C1,C2,1.0", n=20)
            print("Timing OK avg:", statistics.mean(times["ok"]), "s; BAD avg:", statistics.mean(times["bad"]), "s")
            print("Timing OK stdev:", statistics.stdev(times["ok"]), "BAD stdev:", statistics.stdev(times["bad"]))
        else:
            print("No se pudo obtener sesión para timing test.")
