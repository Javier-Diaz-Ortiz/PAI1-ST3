# client.py con menú de Registro / Login y submenú Transacción / Logout
# "Volver al menú principal" ahora realiza LOGOUT real en el servidor.
import socket, json
from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex
import getpass
import sys
import re

HOST = '127.0.0.1'
PORT = 5000

def send_json(conn, obj):
    conn.sendall(json.dumps(obj).encode())

def recv_json(conn):
    data = conn.recv(4096)
    if not data:
        return None
    try:
        return json.loads(data.decode())
    except Exception:
        return None

# Función para validar contraseña segura
def validar_contrasena(password):
    if len(password) < 8:
        return "Debe tener al menos 8 caracteres."
    if not re.search(r"[a-z]", password):
        return "Debe contener al menos una letra minuscula."
    if not re.search(r"[A-Z]", password):
        return "Debe contener al menos una letra mayuscula."
    if not re.search(r"\d", password):
        return "Debe contener al menos un numero."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\\;/]", password):
        return "Debe contener al menos un caracter especial."
    return None

# ---------- Flujos de autenticación ----------
def register(conn):
    print("\n=== Registro ===")
    username = input("Nuevo username: ").strip()
    if not username:
        print("❌ Username vacío")
        return

    pw1 = getpass.getpass("Nueva contraseña: ")
    pw2 = getpass.getpass("Repite la contraseña: ")

    error = validar_contrasena(pw1)
    if error:
        print(f"❌ Contraseña insegura: {error}")
        return
    if pw1 != pw2:
        print("❌ Las contraseñas no coinciden")
        return

    send_json(conn, {"action": "REGISTER", "username": username, "password": pw1})
    resp = recv_json(conn)
    if not resp:
        print("❌ Sin respuesta del servidor")
        return
    if resp.get("status") == "REGISTER_OK":
        print("✅ Registro correcto. Ya puedes iniciar sesión.")
    else:
        print("❌", resp.get("msg", "No se pudo registrar"))

def login(conn):
    print("\n=== Login ===")
    username = input("username: ").strip()
    password = getpass.getpass("password: ")

    # Paso 1: pedir CHALLENGE
    send_json(conn, {"action": "LOGIN_STEP1", "username": username})
    resp = recv_json(conn)

    if not resp:
        print("❌ Sin respuesta del servidor")
        return None, None

    if resp.get("status") == "ERROR":
        print("❌", resp.get("msg", "Usuario o contraseña incorrectos"))
        return None, None

    if resp.get("status") != "CHALLENGE":
        print("❌ Protocolo de login inesperado")
        return None, None

    salt_hex = resp["salt"]
    server_nonce = resp["server_nonce"]

    # Derivar verifier local
    salt = from_hex(salt_hex)
    verifier = derive_verifier(password, salt)

    # Cliente genera su nonce
    client_nonce = gen_nonce_hex(16)

    # HMAC(verifier, client_nonce + server_nonce)
    mac = hmac_sha256(verifier, (client_nonce + server_nonce).encode())

    # Paso 2: enviar respuesta
    send_json(conn, {
        "action": "LOGIN_STEP2",
        "username": username,
        "client_nonce": client_nonce,
        "hmac": to_hex(mac)
    })
    resp2 = recv_json(conn)

    if resp2 and resp2.get("status") == "LOGIN_OK":
        # session_key = HMAC(verifier, client_nonce + server_nonce)
        session_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
        print("✅ Login correcto")
        return username, to_hex(session_key)

    print("❌", (resp2 or {}).get("msg", "Usuario o contraseña incorrectos"))
    return None, None

# ---------- Operaciones autenticadas ----------
def send_transaction(conn, username, session_key_hex):
    print("\n=== Nueva transacción ===")
    payload = input("Introduce transacción (origen,destino,cantidad): ").strip()
    if not payload:
        print("❌ Payload vacío")
        return
    nonce = gen_nonce_hex(8)
    session_key = from_hex(session_key_hex)
    mac = hmac_sha256(session_key, (payload + nonce).encode())
    send_json(conn, {
        "action": "TRANSACTION",
        "username": username,
        "payload": payload,
        "nonce": nonce,
        "hmac": to_hex(mac)
    })
    resp = recv_json(conn)
    if not resp:
        print("❌ Error en transacción")
        return
    elif resp.get("status") == "TRANSACTION_OK":
        print("✅ Transacción aceptada")
    

def logout(conn, username):
    send_json(conn, {"action": "LOGOUT", "username": username})
    resp = recv_json(conn)
    if not resp:
        print("❌ Sin respuesta del servidor")
        return False
    if resp.get("status") == "LOGOUT_OK":
        print("✅ Logout correcto")
        return True
    else:
        print("❌", resp.get("msg", "No se pudo cerrar sesión"))
        return False

# ---------- Menús ----------
def menu_principal():
    print("\n=== Menú principal ===")
    print("1) Registrarse")
    print("2) Login")
    print("3) Salir")
    return input("Elige opción: ").strip()

def menu_autenticado(username):
    print(f"\n=== Menú ({username} autenticado) ===")
    print("1) Hacer transacción")
    print("2) Logout")
    return input("Elige opción: ").strip()

# ---------- Main ----------
if __name__ == "__main__":
    try:
        with socket.create_connection((HOST, PORT)) as s:
            username = None
            session_key_hex = None

            while True:
                if not username:
                    op = menu_principal()
                    if op == "1":
                        register(s)
                    elif op == "2":
                        username, session_key_hex = login(s)
                    elif op == "3":
                        print("👋 Hasta luego")
                        break
                    else:
                        print("Opción no válida")
                else:
                    op = menu_autenticado(username)
                    if op == "1":
                        send_transaction(s, username, session_key_hex)
                    elif op == "2":
                        if logout(s, username):
                            username, session_key_hex = None, None
                    else:
                        print("Opción no válida")
    except ConnectionRefusedError:
        print(f"❌ No se pudo conectar a {HOST}:{PORT}. ¿Está el servidor arrancado?")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹ Interrumpido por el usuario")
        sys.exit(0)
