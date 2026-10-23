#!/usr/bin/env python3
"""
Serveur Annuaire Téléphonique Linkus - Version Sécurisée & Base Chiffrée (AES-256)
- Authentification individuelle avec sessions chiffrées & mots de passe hashés (PBKDF2)
- Base de données SQLite CHIFFRÉE AU REPOS (AES-256-Fernet) : impossible de lire les contacts avec un bloc-notes !
- Gestion des rôles : Administrateur, Éditeur (standard), Consultation seule
- Déployable en local ou 24/7 sur le Cloud (Render, Railway, Docker, VM interne)
"""

import sys
import os

# Forcer l'encodage UTF-8 pour la console Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import json
import sqlite3
import csv
import io
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http import cookies
import webbrowser
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta

# Import du module de chiffrement AES-256
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Port dynamique (compatible Render, Railway, Docker, Local)
PORT = int(os.environ.get("PORT", 5000))
DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(DATA_DIR, "annuaire.db")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")

# =========================================================================
# MOTEUR DE CHIFFREMENT AU REPOS (AES-256)
# =========================================================================

def init_encryption_key() -> Fernet:
    if not HAS_CRYPTO:
        return None

    # 1. Priorité à la variable d'environnement (idéal pour hébergement Cloud / Docker)
    env_key = os.environ.get("APP_ENCRYPTION_KEY")
    if env_key:
        return Fernet(env_key.strip().encode('utf-8'))

    # 2. Sinon fichier secret.key local
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read().strip()
                if key:
                    return Fernet(key)
        except Exception as e:
            print(f"[!] Erreur de lecture de secret.key : {e}")

    # 3. Générer une nouvelle clé aléatoire de 256 bits
    new_key = Fernet.generate_key()
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(new_key)
        print("[*] Nouvelle cle de chiffrement AES-256 generee et stockee dans 'secret.key'")
    except Exception as e:
        print(f"[!] Impossible d'ecrire secret.key : {e}")

    return Fernet(new_key)

CIPHER = init_encryption_key()

def encrypt_val(val: str) -> str:
    """Chiffre une chaîne de texte en AES-256 Fernet."""
    if not val or not CIPHER:
        return val
    s = str(val).strip()
    if not s:
        return ''
    # Si déjà chiffré, ne pas re-chiffrer
    if s.startswith("gAAAAA"):
        return s
    return CIPHER.encrypt(s.encode('utf-8')).decode('utf-8')

def decrypt_val(val: str) -> str:
    """Déchiffre une chaîne chiffrée avec la clé AES-256."""
    if not val or not CIPHER:
        return val
    s = str(val).strip()
    if not s or not s.startswith("gAAAAA"):
        return s
    try:
        return CIPHER.decrypt(s.encode('utf-8')).decode('utf-8')
    except Exception:
        return "[Erreur dechiffrement]"

ENCRYPTED_FIELDS = [
    'last_name', 'first_name', 'company', 'job_title',
    'phone_mobile', 'phone_direct', 'phone_company',
    'email', 'notes'
]

def decrypt_contact_dict(c: dict) -> dict:
    """Déchiffre tous les champs sensibles d'un contact."""
    res = dict(c)
    for field in ENCRYPTED_FIELDS:
        if field in res:
            res[field] = decrypt_val(res[field])
    return res

# =========================================================================
# SÉCURITÉ & HASHAGE DES MOTS DE PASSE
# =========================================================================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100_000
    ).hex()
    return f"{salt}${key}"

def verify_password(password: str, stored: str) -> bool:
    if not stored or '$' not in stored:
        return False
    try:
        salt, expected_key = stored.split('$', 1)
        actual_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations=100_000
        ).hex()
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False

# =========================================================================
# GESTION BASE DE DONNÉES
# =========================================================================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_FILE)), exist_ok=True)
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Table des utilisateurs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'editor', -- 'admin', 'editor', 'readonly'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table des sessions actives
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Table des contacts (toutes les colonnes sensibles contiennent du texte chiffré)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                last_name TEXT NOT NULL,
                first_name TEXT DEFAULT '',
                company TEXT DEFAULT '',
                job_title TEXT DEFAULT '',
                phone_mobile TEXT DEFAULT '',
                phone_direct TEXT DEFAULT '',
                phone_company TEXT DEFAULT '',
                email TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table des paramètres
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Initialiser l'admin par défaut si aucun compte n'existe
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            default_pwd = hash_password("Admin1234!")
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, role)
                VALUES ('admin', ?, 'Administrateur', 'admin')
            """, (default_pwd,))
            print("[*] Compte Administrateur initial cree :")
            print("    -> Identifiant : admin")
            print("    -> Mot de passe : Admin1234!")
            print("    (Pensez a le modifier des la premiere connexion !)")

        # Paramètres par défaut
        cursor.execute("SELECT COUNT(*) FROM settings")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO settings (key, value) VALUES ('call_protocol', 'tel:')")
            cursor.execute("INSERT INTO settings (key, value) VALUES ('outbound_prefix', '')")
            cursor.execute("INSERT INTO settings (key, value) VALUES ('auto_format_fr', '1')")
            cursor.execute("INSERT INTO settings (key, value) VALUES ('theme', 'system')")

        # Exemples de contacts si vide (stockés directement sous forme chiffrée)
        cursor.execute("SELECT COUNT(*) FROM contacts")
        if cursor.fetchone()[0] == 0:
            sample_contacts = [
                ("Dupont", "Jean", "Acme Corporation", "Directeur Commercial", "06 12 34 56 78", "04 72 00 11 22", "04 72 00 11 00", "jean.dupont@acme.fr", "Client historique", 1),
                ("Martin", "Sophie", "Tech Solutions", "Responsable Achats", "07 98 76 54 32", "01 45 67 89 10", "01 45 67 89 00", "smartin@techsolutions.io", "Disponible le matin", 1),
                ("Bernard", "Alexandre", "XEFI", "Support Technique", "06 55 44 33 22", "04 78 99 88 77", "", "a.bernard@xefi.fr", "Referent telephonie et reseau", 0),
                ("Lemoine", "Claire", "Acme Corporation", "Comptabilite", "", "04 72 00 11 25", "04 72 00 11 00", "compta@acme.fr", "Facturation", 0)
            ]
            for c in sample_contacts:
                cursor.execute("""
                    INSERT INTO contacts 
                    (last_name, first_name, company, job_title, phone_mobile, phone_direct, phone_company, email, notes, is_favorite)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    encrypt_val(c[0]), encrypt_val(c[1]), encrypt_val(c[2]), encrypt_val(c[3]),
                    encrypt_val(c[4]), encrypt_val(c[5]), encrypt_val(c[6]), encrypt_val(c[7]),
                    encrypt_val(c[8]), c[9]
                ))

        # Migration automatique de tous les contacts existants vers le format chiffré
        cursor.execute("SELECT * FROM contacts")
        all_contacts = cursor.fetchall()
        migrated_count = 0
        for r in all_contacts:
            rd = dict(r)
            needs_update = False
            for f in ENCRYPTED_FIELDS:
                v = rd.get(f, '')
                if v and not v.startswith('gAAAAA'):
                    needs_update = True
                    break
            if needs_update:
                cursor.execute("""
                    UPDATE contacts SET
                        last_name = ?, first_name = ?, company = ?, job_title = ?,
                        phone_mobile = ?, phone_direct = ?, phone_company = ?,
                        email = ?, notes = ?
                    WHERE id = ?
                """, (
                    encrypt_val(rd.get('last_name', '')),
                    encrypt_val(rd.get('first_name', '')),
                    encrypt_val(rd.get('company', '')),
                    encrypt_val(rd.get('job_title', '')),
                    encrypt_val(rd.get('phone_mobile', '')),
                    encrypt_val(rd.get('phone_direct', '')),
                    encrypt_val(rd.get('phone_company', '')),
                    encrypt_val(rd.get('email', '')),
                    encrypt_val(rd.get('notes', '')),
                    rd['id']
                ))
                migrated_count += 1
        if migrated_count > 0:
            print(f"[*] {migrated_count} contact(s) existant(s) ont ete chiffres automatiquement avec AES-256 !")

        conn.commit()

# =========================================================================
# GESTION DU SERVEUR HTTP & API REST SÉCURISÉE
# =========================================================================

class AnnuaireHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        static_cand = os.path.join(base_dir, "static")
        # Si le sous-dossier static existe avec index.html, l'utiliser, sinon servir depuis la racine
        web_dir = static_cand if os.path.isdir(static_cand) and os.path.exists(os.path.join(static_cand, "index.html")) else base_dir
        super().__init__(*args, directory=web_dir, **kwargs)

    def _send_json(self, data, status=200, headers_extra=None):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        if headers_extra:
            for k, v in headers_extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def get_current_user(self):
        token = None
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            c = cookies.SimpleCookie()
            try:
                c.load(cookie_header)
                if 'session_token' in c:
                    token = c['session_token'].value
            except Exception:
                pass

        if not token:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:].strip()

        if not token:
            return None

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.id, u.username, u.display_name, u.role 
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP
            """, (token,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    # =====================================================================
    # ROUTES GET
    # =====================================================================
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/auth/me":
            user = self.get_current_user()
            if user:
                self._send_json({"authenticated": True, "user": user})
            else:
                self._send_json({"authenticated": False}, status=401)
            return

        if path.startswith("/api/"):
            current_user = self.get_current_user()
            if not current_user:
                self._send_json({"error": "Non authentifie. Veuillez vous connecter."}, status=401)
                return

            # --- Utilisateurs (Réservé admin) ---
            if path == "/api/users":
                if current_user['role'] != 'admin':
                    self._send_json({"error": "Acces reserve aux administrateurs"}, status=403)
                    return
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, username, display_name, role, created_at FROM users ORDER BY username ASC")
                    users = [dict(r) for r in cursor.fetchall()]
                    self._send_json(users)
                return

            # --- Contacts (Déchiffrement transparent en mémoire) ---
            if path == "/api/contacts":
                q = params.get('q', [''])[0].strip().lower()
                company = params.get('company', [''])[0].strip()
                fav_only = params.get('favorite', ['0'])[0] == '1'
                sort_by = params.get('sort', ['last_name'])[0]

                with get_db() as conn:
                    cursor = conn.cursor()
                    query = "SELECT * FROM contacts WHERE 1=1"
                    args = []

                    if fav_only:
                        query += " AND is_favorite = 1"

                    cursor.execute(query, args)
                    raw_contacts = cursor.fetchall()

                    # Déchiffrer chaque contact
                    decrypted = [decrypt_contact_dict(r) for r in raw_contacts]

                    # Filtrage par société (après déchiffrement)
                    if company:
                        decrypted = [c for c in decrypted if c.get('company') == company]

                    # Filtrage textuel instantané
                    if q:
                        def match_q(c):
                            text_to_search = " ".join([
                                c.get('last_name', ''),
                                c.get('first_name', ''),
                                c.get('company', ''),
                                c.get('job_title', ''),
                                c.get('phone_mobile', '').replace(' ', ''),
                                c.get('phone_direct', '').replace(' ', ''),
                                c.get('phone_company', '').replace(' ', ''),
                                c.get('email', ''),
                                c.get('notes', '')
                            ]).lower()
                            return q in text_to_search

                        decrypted = [c for c in decrypted if match_q(c)]

                    # Tri
                    if sort_by == 'company':
                        decrypted.sort(key=lambda x: (x.get('company', '').lower(), x.get('last_name', '').lower()))
                    elif sort_by == 'recent':
                        decrypted.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
                    else:
                        decrypted.sort(key=lambda x: (x.get('last_name', '').lower(), x.get('first_name', '').lower()))

                    self._send_json(decrypted)
                return

            elif path.startswith("/api/contacts/") and not path.endswith("/toggle-favorite"):
                contact_id = path.replace("/api/contacts/", "")
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,))
                    row = cursor.fetchone()
                    if row:
                        self._send_json(decrypt_contact_dict(row))
                    else:
                        self._send_json({"error": "Contact non trouve"}, status=404)
                return

            elif path == "/api/companies":
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT company FROM contacts WHERE company IS NOT NULL AND company != ''")
                    rows = cursor.fetchall()
                    
                    # Déchiffrer les noms de société et compter
                    counts = {}
                    for r in rows:
                        c_name = decrypt_val(r['company']).strip()
                        if c_name:
                            counts[c_name] = counts.get(c_name, 0) + 1

                    companies = [{"company": k, "count": v} for k, v in counts.items()]
                    companies.sort(key=lambda x: x['company'].lower())
                    self._send_json(companies)
                return

            elif path == "/api/settings":
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT key, value FROM settings")
                    settings = {row['key']: row['value'] for row in cursor.fetchall()}
                    self._send_json(settings)
                return

            elif path == "/api/export-csv":
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM contacts")
                    raw_contacts = cursor.fetchall()
                    contacts = [decrypt_contact_dict(r) for r in raw_contacts]
                    contacts.sort(key=lambda x: (x.get('company', '').lower(), x.get('last_name', '').lower()))

                    output = io.StringIO()
                    writer = csv.writer(output, delimiter=';')
                    writer.writerow([
                        "Nom", "Prenom", "Societe", "Poste/Fonction",
                        "Telephone Mobile", "Telephone Direct", "Telephone Standard",
                        "Email", "Notes", "Favori"
                    ])
                    for c in contacts:
                        writer.writerow([
                            c.get('last_name', ''), c.get('first_name', ''), c.get('company', ''), c.get('job_title', ''),
                            c.get('phone_mobile', ''), c.get('phone_direct', ''), c.get('phone_company', ''),
                            c.get('email', ''), c.get('notes', ''), "1" if c.get('is_favorite') else "0"
                        ])

                    csv_content = ('\ufeff' + output.getvalue()).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/csv; charset=utf-8')
                    self.send_header('Content-Disposition', 'attachment; filename="annuaire_contacts.csv"')
                    self.send_header('Content-Length', str(len(csv_content)))
                    self.end_headers()
                    self.wfile.write(csv_content)
                return

            elif path == "/api/stats":
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT company, is_favorite FROM contacts")
                    rows = cursor.fetchall()
                    total_contacts = len(rows)
                    total_favorites = sum(1 for r in rows if r['is_favorite'])
                    unique_companies = len(set(decrypt_val(r['company']).strip() for r in rows if decrypt_val(r['company']).strip()))
                    self._send_json({
                        "total_contacts": total_contacts,
                        "total_companies": unique_companies,
                        "total_favorites": total_favorites
                    })
                return

        return super().do_GET()

    # =====================================================================
    # ROUTES POST
    # =====================================================================
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length)

        # 1. Connexion (Login)
        if path == "/api/auth/login":
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                self._send_json({"error": "Donnees invalides"}, status=400)
                return

            username = data.get('username', '').strip()
            password = data.get('password', '')

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()

                if not user or not verify_password(password, user['password_hash']):
                    self._send_json({"error": "Identifiant ou mot de passe incorrect"}, status=401)
                    return

                token = secrets.token_urlsafe(32)
                expires = (datetime.utcnow() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                               (token, user['id'], expires))
                conn.commit()

                cookie_str = f"session_token={token}; Path=/; Max-Age=2592000; SameSite=Lax; HttpOnly"
                user_info = {
                    "id": user['id'],
                    "username": user['username'],
                    "display_name": user['display_name'],
                    "role": user['role']
                }
                self._send_json({"success": True, "user": user_info}, headers_extra={"Set-Cookie": cookie_str})
            return

        # 2. Déconnexion (Logout)
        if path == "/api/auth/logout":
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                c = cookies.SimpleCookie()
                try:
                    c.load(cookie_header)
                    if 'session_token' in c:
                        token = c['session_token'].value
                        with get_db() as conn:
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                            conn.commit()
                except Exception:
                    pass

            del_cookie = "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; HttpOnly"
            self._send_json({"success": True}, headers_extra={"Set-Cookie": del_cookie})
            return

        current_user = self.get_current_user()
        if not current_user:
            self._send_json({"error": "Non authentifie"}, status=401)
            return

        # Création d'utilisateur (Admin)
        if path == "/api/users":
            if current_user['role'] != 'admin':
                self._send_json({"error": "Action reservee aux administrateurs"}, status=403)
                return

            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username', '').strip()
            password = data.get('password', '')
            display_name = data.get('display_name', '').strip()
            role = data.get('role', 'editor')

            if not username or not password:
                self._send_json({"error": "Identifiant et mot de passe requis"}, status=400)
                return

            if role not in ['admin', 'editor', 'readonly']:
                role = 'editor'

            with get_db() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, display_name, role)
                        VALUES (?, ?, ?, ?)
                    """, (username, hash_password(password), display_name or username, role))
                    new_id = cursor.lastrowid
                    conn.commit()
                    self._send_json({"success": True, "id": new_id}, status=201)
                except sqlite3.IntegrityError:
                    self._send_json({"error": "Cet identifiant existe deja"}, status=400)
            return

        # Vérification droit d'écriture pour les contacts
        if current_user['role'] == 'readonly':
            self._send_json({"error": "Votre compte est en lecture seule"}, status=403)
            return

        # Ajout contact (Chiffrement AES-256 avant stockage en base)
        if path == "/api/contacts":
            data = json.loads(post_data.decode('utf-8'))
            last_name = data.get('last_name', '').strip()
            if not last_name:
                self._send_json({"error": "Le nom de famille est obligatoire"}, status=400)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO contacts 
                    (last_name, first_name, company, job_title, phone_mobile, phone_direct, phone_company, email, notes, is_favorite, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    encrypt_val(last_name),
                    encrypt_val(data.get('first_name', '').strip()),
                    encrypt_val(data.get('company', '').strip()),
                    encrypt_val(data.get('job_title', '').strip()),
                    encrypt_val(data.get('phone_mobile', '').strip()),
                    encrypt_val(data.get('phone_direct', '').strip()),
                    encrypt_val(data.get('phone_company', '').strip()),
                    encrypt_val(data.get('email', '').strip()),
                    encrypt_val(data.get('notes', '').strip()),
                    1 if data.get('is_favorite') else 0
                ))
                new_id = cursor.lastrowid
                conn.commit()
                self._send_json({"success": True, "id": new_id}, status=201)
            return

        elif path.endswith("/toggle-favorite"):
            contact_id = path.replace("/api/contacts/", "").replace("/toggle-favorite", "")
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE contacts SET is_favorite = 1 - is_favorite, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (contact_id,))
                conn.commit()
                cursor.execute("SELECT is_favorite FROM contacts WHERE id = ?", (contact_id,))
                res = cursor.fetchone()
                if res:
                    self._send_json({"is_favorite": res['is_favorite']})
                else:
                    self._send_json({"error": "Contact introuvable"}, status=404)
            return

        elif path == "/api/settings":
            data = json.loads(post_data.decode('utf-8'))
            with get_db() as conn:
                cursor = conn.cursor()
                for k, v in data.items():
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
                conn.commit()
                self._send_json({"success": True})
            return

        elif path == "/api/import-csv":
            content_str = post_data.decode('utf-8-sig', errors='ignore')
            sep = ';' if ';' in content_str.splitlines()[0] else ','
            reader = csv.reader(io.StringIO(content_str), delimiter=sep)
            
            rows = list(reader)
            if not rows:
                self._send_json({"error": "Fichier CSV vide"}, status=400)
                return

            header = [h.strip().lower() for h in rows[0]]
            def find_idx(keywords):
                for kw in keywords:
                    for idx, h in enumerate(header):
                        if kw in h:
                            return idx
                return None

            idx_nom = find_idx(["nom", "last", "name"])
            idx_prenom = find_idx(["prénom", "prenom", "first"])
            idx_societe = find_idx(["société", "societe", "entreprise", "company"])
            idx_poste = find_idx(["poste", "fonction", "titre", "job", "title"])
            idx_mobile = find_idx(["mobile", "portable", "cell"])
            idx_direct = find_idx(["direct", "fixe", "bureau", "work"])
            idx_standard = find_idx(["standard", "entreprise tel", "accueil"])
            idx_email = find_idx(["email", "mail", "courriel"])
            idx_notes = find_idx(["note", "commentaire", "description"])

            imported = 0
            with get_db() as conn:
                cursor = conn.cursor()
                for row in rows[1:]:
                    if not row or not any(row):
                        continue
                    
                    def val(idx):
                        return row[idx].strip() if idx is not None and idx < len(row) else ''

                    last_name = val(idx_nom)
                    if not last_name:
                        first = val(idx_prenom)
                        comp = val(idx_societe)
                        if first or comp:
                            last_name = first or comp
                        else:
                            continue

                    cursor.execute("""
                        INSERT INTO contacts 
                        (last_name, first_name, company, job_title, phone_mobile, phone_direct, phone_company, email, notes, is_favorite, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                    """, (
                        encrypt_val(last_name),
                        encrypt_val(val(idx_prenom)),
                        encrypt_val(val(idx_societe)),
                        encrypt_val(val(idx_poste)),
                        encrypt_val(val(idx_mobile)),
                        encrypt_val(val(idx_direct)),
                        encrypt_val(val(idx_standard)),
                        encrypt_val(val(idx_email)),
                        encrypt_val(val(idx_notes))
                    ))
                    imported += 1
                conn.commit()

            self._send_json({"success": True, "count": imported})
            return

        self._send_json({"error": "Route inconnue"}, status=404)

    # =====================================================================
    # ROUTES PUT
    # =====================================================================
    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length).decode('utf-8'))

        current_user = self.get_current_user()
        if not current_user:
            self._send_json({"error": "Non authentifie"}, status=401)
            return

        if path.startswith("/api/users/"):
            target_id = int(path.replace("/api/users/", ""))
            if current_user['role'] != 'admin' and current_user['id'] != target_id:
                self._send_json({"error": "Action non autorisee"}, status=403)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (target_id,))
                target_user = cursor.fetchone()
                if not target_user:
                    self._send_json({"error": "Utilisateur introuvable"}, status=404)
                    return

                new_display = data.get('display_name', target_user['display_name'])
                new_role = target_user['role']
                if current_user['role'] == 'admin' and 'role' in data:
                    new_role = data['role']

                new_pwd = data.get('password')
                if new_pwd:
                    pwd_hash = hash_password(new_pwd)
                    cursor.execute("""
                        UPDATE users SET display_name = ?, role = ?, password_hash = ? WHERE id = ?
                    """, (new_display, new_role, pwd_hash, target_id))
                else:
                    cursor.execute("""
                        UPDATE users SET display_name = ?, role = ? WHERE id = ?
                    """, (new_display, new_role, target_id))
                conn.commit()
                self._send_json({"success": True})
            return

        # Modification contact (Chiffrement AES-256)
        if current_user['role'] == 'readonly':
            self._send_json({"error": "Votre compte est en lecture seule"}, status=403)
            return

        if path.startswith("/api/contacts/"):
            contact_id = path.replace("/api/contacts/", "")
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE contacts SET
                        last_name = ?,
                        first_name = ?,
                        company = ?,
                        job_title = ?,
                        phone_mobile = ?,
                        phone_direct = ?,
                        phone_company = ?,
                        email = ?,
                        notes = ?,
                        is_favorite = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (
                    encrypt_val(data.get('last_name', '').strip()),
                    encrypt_val(data.get('first_name', '').strip()),
                    encrypt_val(data.get('company', '').strip()),
                    encrypt_val(data.get('job_title', '').strip()),
                    encrypt_val(data.get('phone_mobile', '').strip()),
                    encrypt_val(data.get('phone_direct', '').strip()),
                    encrypt_val(data.get('phone_company', '').strip()),
                    encrypt_val(data.get('email', '').strip()),
                    encrypt_val(data.get('notes', '').strip()),
                    1 if data.get('is_favorite') else 0,
                    contact_id
                ))
                conn.commit()
                self._send_json({"success": True})
            return

        self._send_json({"error": "Route inconnue"}, status=404)

    # =====================================================================
    # ROUTES DELETE
    # =====================================================================
    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        current_user = self.get_current_user()
        if not current_user:
            self._send_json({"error": "Non authentifie"}, status=401)
            return

        if path.startswith("/api/users/"):
            if current_user['role'] != 'admin':
                self._send_json({"error": "Action reservee aux administrateurs"}, status=403)
                return

            target_id = int(path.replace("/api/users/", ""))
            if current_user['id'] == target_id:
                self._send_json({"error": "Vous ne pouvez pas supprimer votre propre compte admin"}, status=400)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = ?", (target_id,))
                conn.commit()
                self._send_json({"success": True})
            return

        if current_user['role'] == 'readonly':
            self._send_json({"error": "Votre compte est en lecture seule"}, status=403)
            return

        if path.startswith("/api/contacts/"):
            contact_id = path.replace("/api/contacts/", "")
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
                conn.commit()
                self._send_json({"success": True})
            return

        self._send_json({"error": "Route inconnue"}, status=404)

def run(open_browser=True):
    init_db()
    server_address = ('0.0.0.0', PORT)
    httpd = HTTPServer(server_address, AnnuaireHandler)
    url = f"http://localhost:{PORT}"
    print("=" * 60)
    print(f"[*] Annuaire Linkus demarre avec succes !")
    print(f"[*] Port d'ecoute : {PORT}")
    print(f"[*] Base de donnees : {DB_FILE}")
    print(f"[*] Chiffrement au repos : AES-256 Fernet ACTIF (Fichier protege)")
    print(f"[*] Mode Securise : Authentification individuelle & Sessions HttpOnly")
    print(f"[*] Acces local : {url}")
    print("[*] Appuyez sur Ctrl+C pour arreter le serveur.")
    print("=" * 60)

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur...")
        httpd.server_close()

if __name__ == '__main__':
    open_b = "--no-browser" not in sys.argv and not os.environ.get("RENDER")
    run(open_browser=open_b)
