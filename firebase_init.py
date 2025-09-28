# firebase_init.py
import firebase_admin
from firebase_admin import credentials, firestore
import os

def init_firebase(service_account_path: str = "serviceAccountKey.json"):
    if not os.path.exists(service_account_path):
        raise FileNotFoundError(f"Service account JSON not found at {service_account_path}")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    return db

if __name__ == "__main__":
    db = init_firebase()
    print("Firebase inicializado. Referencia a DB obtenida.")
