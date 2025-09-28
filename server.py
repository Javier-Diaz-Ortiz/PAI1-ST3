import socket, threading, json, binascii
from firebase_init import init_firebase
from crypto_utils import generate_salt, derive_verifier, hmac_sha256, secure_compare, gen_nonce_hex, from_hex, to_hex
from firebase_admin import firestore
import time
import logging

# --- Configuración de logs ---
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# --- Configuración básica ---
HOST = "0.0.0.0"
PORT = 5000

# --- Inicializar Firebase ---
db = init_firebase()
USERS_COLLECTION = "users"
TRANSACTIONS_COLLECTION = "transactions"

# --- Gestión de sesiones y seguridad ---
sessions = {}           # { username: {verifier, client_nonce, server_nonce, last_nonce} }
login_attempts = {}     # { username: {"fails": int, "last_fail": timestamp} }
blocked_users = {}      # { username: unblock_timestamp }

MAX_FAILS = 3
BLOCK_TIME = 60  # segundos de bloqueo

# --- Funciones principales ---
def handle_register(conn, data):
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        conn.send(json.dumps({"status": "ERROR", "msg": "Faltan credenciales"}).encode())
        return

    user_ref = db.collection(USERS_COLLECTION).document(username)
    if user_ref.get().exists:
        conn.send(json.dumps({"status": "ERROR", "msg": "Usuario ya existe"}).encode())
        return

    salt = generate_salt()
    verifier = derive_verifier(password, salt)
    user_ref.set({
        "salt": to_hex(salt),
        "verifier": to_hex(verifier),
        "created_at": firestore.SERVER_TIMESTAMP
    })

    logging.info(f"REGISTER_OK user={username}")
    conn.send(json.dumps({"status": "REGISTER_OK"}).encode())

def handle_login_step1(conn, data):
    username = data.get("username")
    if not username:
        conn.send(json.dumps({"status": "ERROR", "msg": "Falta username"}).encode())
        return

    # Bloqueo por fuerza bruta
    if username in blocked_users:
        if time.time() < blocked_users[username]:
            conn.send(json.dumps({"status": "ERROR", "msg": "Usuario bloqueado temporalmente"}).encode())
            return
        else:
            blocked_users.pop(username)

    user_ref = db.collection(USERS_COLLECTION).document(username).get()
    if not user_ref.exists:
        conn.send(json.dumps({"status": "ERROR", "msg": "Usuario no encontrado"}).encode())
        return

    user_data = user_ref.to_dict()
    salt = user_data["salt"]
    server_nonce = gen_nonce_hex(16)

    # Guardar nonce temporal
    sessions[username] = {"server_nonce": server_nonce, "verifier": from_hex(user_data["verifier"])}

    conn.send(json.dumps({"status": "CHALLENGE", "salt": salt, "server_nonce": server_nonce}).encode())

def handle_login_step2(conn, data):
    username = data.get("username")
    client_nonce = data.get("client_nonce")
    client_hmac = from_hex(data.get("hmac"))

    if username not in sessions:
        conn.send(json.dumps({"status": "ERROR", "msg": "Sesión no iniciada"}).encode())
        return

    verifier = sessions[username]["verifier"]
    server_nonce = sessions[username]["server_nonce"]

    expected_hmac = hmac_sha256(verifier, (client_nonce + server_nonce).encode())

    if secure_compare(expected_hmac, client_hmac):
        # login correcto -> resetear contador fallos
        login_attempts[username] = {"fails": 0, "last_fail": None}
        sessions[username].update({"client_nonce": client_nonce, "last_nonce": None})

        logging.info(f"LOGIN_OK user={username}")
        conn.send(json.dumps({"status": "LOGIN_OK"}).encode())
    else:
        # login fallido -> aumentar contador
        entry = login_attempts.get(username, {"fails": 0, "last_fail": None})
        entry["fails"] += 1
        entry["last_fail"] = time.time()
        login_attempts[username] = entry

        if entry["fails"] >= MAX_FAILS:
            blocked_users[username] = time.time() + BLOCK_TIME
            logging.warning(f"LOGIN_BLOCK user={username}")
            conn.send(json.dumps({"status": "ERROR", "msg": "Usuario bloqueado por fallos"}).encode())
        else:
            logging.warning(f"LOGIN_FAIL user={username}")
            conn.send(json.dumps({"status": "ERROR", "msg": "Credenciales inválidas"}).encode())

def handle_transaction(conn, data):
    username = data.get("username")
    payload = data.get("payload")
    nonce = data.get("nonce")
    received_hmac = from_hex(data.get("hmac"))

    if username not in sessions or "client_nonce" not in sessions[username]:
        conn.send(json.dumps({"status": "ERROR", "msg": "Usuario no autenticado"}).encode())
        return

    # Replay attack check
    if sessions[username].get("last_nonce") == nonce:
        logging.warning(f"TRANSACTION_FAIL user={username} reason=replay_detected")
        conn.send(json.dumps({"status": "ERROR", "msg": "Replay detectado"}).encode())
        return

    verifier = sessions[username]["verifier"]
    client_nonce = sessions[username]["client_nonce"]
    server_nonce = sessions[username]["server_nonce"]

    session_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
    expected_hmac = hmac_sha256(session_key, (payload + nonce).encode())

    if secure_compare(expected_hmac, received_hmac):
        sessions[username]["last_nonce"] = nonce

        origen, destino, cantidad = payload.split(",")
        db.collection(TRANSACTIONS_COLLECTION).add({
            "from": origen.strip(),
            "to": destino.strip(),
            "amount": float(cantidad),
            "payload": payload,
            "nonce": nonce,
            "hmac": to_hex(received_hmac),
            "timestamp": firestore.SERVER_TIMESTAMP
        })

        logging.info(f"TRANSACTION_OK user={username} payload={payload} nonce={nonce}")
        conn.send(json.dumps({"status": "TRANSACTION_OK"}).encode())
    else:
        logging.warning(f"TRANSACTION_FAIL user={username} reason=integrity_error")
        conn.send(json.dumps({"status": "ERROR", "msg": "Integridad fallida"}).encode())

def handle_logout(conn, data):
    username = data.get("username")
    if username in sessions:
        sessions.pop(username)
        logging.info(f"LOGOUT_OK user={username}")
        conn.send(json.dumps({"status": "LOGOUT_OK"}).encode())
    else:
        conn.send(json.dumps({"status": "ERROR", "msg": "Usuario no tenía sesión activa"}).encode())

# --- Hilo por cliente ---
def client_thread(conn, addr):
    print(f"Conexión desde {addr}")
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            data = json.loads(data.decode())

            action = data.get("action")
            if action == "REGISTER":
                handle_register(conn, data)
            elif action == "LOGIN_STEP1":
                handle_login_step1(conn, data)
            elif action == "LOGIN_STEP2":
                handle_login_step2(conn, data)
            elif action == "TRANSACTION":
                handle_transaction(conn, data)
            elif action == "LOGOUT":
                handle_logout(conn, data)
            else:
                conn.send(json.dumps({"status": "ERROR", "msg": "Acción desconocida"}).encode())
        except Exception as e:
            print(f"Error: {e}")
            break
    conn.close()

# --- Main ---
if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Servidor escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()
