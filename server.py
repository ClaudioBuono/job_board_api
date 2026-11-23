# ============================================================
#  BACK-END "Bacheca annunci di lavoro"  (parte 1: R1, R2, R3)
#  Python + Flask. Dati salvati in un file JSON (persistenti).
# ============================================================
import json
import os
import secrets
import threading
import uuid
from functools import wraps

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

PORT = 3000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'data', 'db.json')
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

# Il server può gestire più richieste insieme: il lock evita che due
# richieste scrivano il file nello stesso momento.
lock = threading.Lock()


# ---------- "Database": un dizionario in memoria salvato su file ----------
def load_db():
    if not os.path.exists(DB_FILE):
        return {'companies': [], 'jobs': [], 'applications': [], 'tokens': {}}
    with open(DB_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


db = load_db()


def save_db():
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


# ---------- Autenticazione ----------
# Un "decoratore": si scrive @auth sopra una funzione per renderla riservata.
# Controlla l'header "Authorization: Bearer <token>".
def auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        token = header.replace('Bearer ', '')
        company_id = db['tokens'].get(token)
        if company_id is None:
            return jsonify(error='Non autenticato'), 401
        g.company_id = company_id
        g.token = token
        return func(*args, **kwargs)

    return wrapper


app = Flask(__name__)


# ================= R1 - Registrazione =================
@app.post('/api/register')
def register():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    if not name or not email or not password:
        return jsonify(error='Compila tutti i campi'), 400
    if len(password) < 6:
        return jsonify(error='La password deve avere almeno 6 caratteri'), 400

    with lock:
        if any(c['email'] == email for c in db['companies']):
            return jsonify(error='Email già registrata'), 409
        db['companies'].append({
            'id': str(uuid.uuid4()),
            'name': name,
            'email': email,
            # mai la password in chiaro: si salva solo l'hash
            'passwordHash': generate_password_hash(password),
        })
        save_db()
    return jsonify(ok=True), 201


# ================= R2 - Login =================
# Se le credenziali sono giuste genera un token casuale da usare nelle richieste successive.
@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    company = next((c for c in db['companies'] if c['email'] == email), None)
    if company is None or not check_password_hash(company['passwordHash'], password):
        return jsonify(error='Email o password errate'), 401

    token = secrets.token_hex(32)
    with lock:
        db['tokens'][token] = company['id']
        save_db()
    return jsonify(
        token=token,
        company={'id': company['id'], 'name': company['name'], 'email': company['email']},
    )


# ================= R3 - Logout =================
# Il token viene cancellato dal server e non vale più.
@app.post('/api/logout')
@auth
def logout():
    with lock:
        db['tokens'].pop(g.token, None)
        save_db()
    return jsonify(ok=True)


if __name__ == '__main__':
    # host 0.0.0.0 = raggiungibile anche dal telefono (stessa rete Wi-Fi)
    app.run(host='0.0.0.0', port=PORT)