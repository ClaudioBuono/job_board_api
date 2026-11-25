from datetime import datetime, timezone
import json
import os
import secrets
import threading
import uuid
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

PORT = 3000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'data', 'db.json')
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')  # qui finiscono i curriculum
os.makedirs(UPLOAD_DIR, exist_ok=True)
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


# ================= R4 - Pubblicazione annuncio (solo azienda loggata) =================
@app.post('/api/jobs')
@auth
def create_job():
    data = request.get_json(silent=True) or {}
    title = str(data.get('title', '')).strip()
    description = str(data.get('description', '')).strip()
    if not title or not description:
        return jsonify(error='Titolo e descrizione sono obbligatori'), 400
 
    job = {
        'id': str(uuid.uuid4()),
        'companyId': g.company_id,  # messo da @auth: l'annuncio appartiene all'azienda loggata
        'title': title,
        'description': description,
        'createdAt': datetime.now(timezone.utc).isoformat(),
    }
    with lock:
        db['jobs'].append(job)
        save_db()
    return jsonify(job), 201
 
 
# ================= R5 - Consultazione bacheca (pubblica, senza login) =================
def company_name(company_id):
    company = next((c for c in db['companies'] if c['id'] == company_id), None)
    return company['name'] if company else 'Azienda'
 
 
@app.get('/api/jobs')
def list_jobs():
    # dal più recente al più vecchio, aggiungendo il nome dell'azienda
    jobs = [{**job, 'companyName': company_name(job['companyId'])} for job in reversed(db['jobs'])]
    return jsonify(jobs)

 
# ================= R6 - Candidatura (pubblica, il candidato non fa login) =================
# La richiesta è "multipart/form-data": campi di testo (request.form) + file (request.files).
@app.post('/api/jobs/<job_id>/applications')
def apply_to_job(job_id):
    job = next((j for j in db['jobs'] if j['id'] == job_id), None)
    if job is None:
        return jsonify(error='Annuncio non trovato'), 404
 
    first_name = request.form.get('firstName', '').strip()
    last_name = request.form.get('lastName', '').strip()
    email = request.form.get('email', '').strip()
    cv = request.files.get('cv')
 
    # Prima si controlla TUTTO, poi si salva il file (così non restano file orfani)
    if not first_name or not last_name or not email or cv is None or cv.filename == '':
        return jsonify(error='Nome, cognome, email e curriculum sono obbligatori'), 400
    if '@' not in email:
        return jsonify(error='Email non valida'), 400
    if not cv.filename.lower().endswith('.pdf'):
        return jsonify(error='Il curriculum deve essere un file PDF'), 400
    if cv.stream.read(5) != b'%PDF-':  # ogni PDF inizia con questi 5 caratteri
        return jsonify(error='Il file non è un PDF valido'), 400
    cv.stream.seek(0)  # riporta il file all'inizio prima di salvarlo
 
    # Nome casuale: evita sovrascritture e non si può indovinare
    stored_name = uuid.uuid4().hex + '.pdf'
    cv.save(os.path.join(UPLOAD_DIR, stored_name))
 
    application = {
        'id': str(uuid.uuid4()),
        'jobId': job['id'],
        'firstName': first_name,
        'lastName': last_name,
        'email': email,
        'cvPath': '/uploads/' + stored_name,
        'cvOriginalName': cv.filename,
        'createdAt': datetime.now(timezone.utc).isoformat(),
    }
    with lock:
        db['applications'].append(application)
        save_db()
    return jsonify(ok=True), 201
 
 
# Permette di scaricare/aprire un curriculum da un indirizzo, es. /uploads/abc123.pdf
@app.get('/uploads/<path:filename>')
def get_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)
 
 
# ================= R7 - Consultazione candidature (solo azienda loggata) =================
# I miei annunci, con il numero di candidature ricevute
@app.get('/api/my/jobs')
@auth
def my_jobs():
    jobs = []
    for job in reversed(db['jobs']):
        if job['companyId'] == g.company_id:  # solo gli annunci di questa azienda
            count = sum(1 for a in db['applications'] if a['jobId'] == job['id'])
            jobs.append({**job, 'applicationsCount': count})
    return jsonify(jobs)
 
 
# Le candidature di UN mio annuncio
@app.get('/api/my/jobs/<job_id>/applications')
@auth
def job_applications(job_id):
    # L'annuncio deve esistere E appartenere all'azienda loggata:
    # altrimenti un'azienda potrebbe leggere le candidature degli altri.
    job = next(
        (j for j in db['jobs'] if j['id'] == job_id and j['companyId'] == g.company_id),
        None,
    )
    if job is None:
        return jsonify(error='Annuncio non trovato'), 404
    applications = [a for a in reversed(db['applications']) if a['jobId'] == job_id]
    return jsonify(applications)
 
 
if __name__ == '__main__':
    # host 0.0.0.0 = raggiungibile anche dal telefono (stessa rete Wi-Fi)
    app.run(host='0.0.0.0', port=PORT)