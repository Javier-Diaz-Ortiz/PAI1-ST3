# init_users.py
from firebase_init import init_firebase
from crypto_utils import generate_salt, derive_verifier, to_hex

db = init_firebase()
USERS_COLLECTION = 'users'

def add_user(username, password):
    salt = generate_salt()
    verifier = derive_verifier(password, salt)
    db.collection(USERS_COLLECTION).document(username).set({
        'salt': to_hex(salt),
        'verifier': to_hex(verifier)
    })
    print(f"Usuario {username} creado en Firestore")

if __name__ == "__main__":
    pre_users = {
        "alice": "alice123",
        "bob": "bob123",
        "charlie": "charlie123"
    }
    for u, p in pre_users.items():
        add_user(u, p)
