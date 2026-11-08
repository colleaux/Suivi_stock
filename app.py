import datetime
import hmac
import io
import math
import os
import re
import secrets
import warnings

import psycopg
from PIL import Image, UnidentifiedImageError
from psycopg.rows import dict_row
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH")
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"

if not app.config["SECRET_KEY"]:
  raise RuntimeError("La variable d'environnement SECRET_KEY doit être définie.")
if len(app.config["SECRET_KEY"]) < 32:
  raise RuntimeError("SECRET_KEY doit contenir au moins 32 caractères.")
if not DATABASE_URL:
  raise RuntimeError("La variable d'environnement DATABASE_URL doit être définie.")

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Connexion - Suivi Inventaire</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        html { -webkit-text-size-adjust: 100%; }
        @media (max-width: 767px) {
            input { font-size: 16px !important; }
            button { min-height: 44px; }
        }
    </style>
</head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center p-4">
    <main class="w-full max-w-sm bg-white rounded-lg shadow p-6">
        <h1 class="text-lg font-bold text-slate-900 mb-5">Connexion au suivi de stock</h1>
        {% if error %}<p role="alert" class="text-sm text-rose-700 mb-4">{{ error }}</p>{% endif %}
        <form method="POST" class="space-y-4">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label class="block text-sm font-medium text-slate-700">
                Identifiant
                <input name="username" autocomplete="username" required class="mt-1 w-full border rounded p-2">
            </label>
            <label class="block text-sm font-medium text-slate-700">
                Mot de passe
                <input type="password" name="password" autocomplete="current-password" required class="mt-1 w-full border rounded p-2">
            </label>
            <button type="submit" class="w-full bg-emerald-900 text-white rounded p-2 font-semibold">Se connecter</button>
        </form>
    </main>
</body>
</html>
"""

def allowed_file(filename):
  return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_image(upload):
  if not upload or not upload.filename:
    return None
  if not allowed_file(upload.filename):
    abort(400, description="Format d'image non autorisé.")
  image_data = upload.read()
  try:
    with warnings.catch_warnings():
      warnings.simplefilter("error", Image.DecompressionBombWarning)
      image = Image.open(io.BytesIO(image_data))
      image_format = image.format
      image.verify()
  except (
      UnidentifiedImageError,
      OSError,
      Image.DecompressionBombError,
      Image.DecompressionBombWarning,
  ):
    abort(400, description="Le fichier envoyé n'est pas une image valide.")
  expected_formats = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP"}
  extension = upload.filename.rsplit(".", 1)[1].lower()
  if image_format != expected_formats[extension]:
    abort(400, description="L'extension ne correspond pas au format de l'image.")
  filename = f"art_{secrets.token_hex(8)}_{secure_filename(upload.filename)}"
  with open(os.path.join(app.config["UPLOAD_FOLDER"], filename), "wb") as image_file:
    image_file.write(image_data)
  return filename


def form_integer(field, default=None, minimum=None):
  value = request.form.get(field)
  if value in (None, ""):
    if default is not None:
      return default
    abort(400, description=f"Le champ {field} est obligatoire.")
  try:
    result = int(value)
  except (TypeError, ValueError):
    abort(400, description=f"Le champ {field} doit être un nombre entier.")
  if minimum is not None and result < minimum:
    abort(400, description=f"Le champ {field} doit être supérieur ou égal à {minimum}.")
  return result


def optional_integer(value, field):
  if value in (None, ""):
    return None
  try:
    result = int(value)
  except (TypeError, ValueError):
    abort(400, description=f"Le champ {field} doit être un nombre entier.")
  if result < 1:
    abort(400, description=f"Le champ {field} doit être supérieur à zéro.")
  return result


def form_price(field="price"):
  value = request.form.get(field, "0")
  try:
    result = float(value or 0)
  except (TypeError, ValueError):
    abort(400, description="Le prix doit être un nombre valide.")
  if not math.isfinite(result) or result < 0:
    abort(400, description="Le prix doit être positif ou nul.")
  return result


def is_usable_password_hash(password_hash):
  if not isinstance(password_hash, str):
    return False
  parts = password_hash.split("$", 2)
  if len(parts) != 3 or not parts[1] or not re.fullmatch(r"[0-9a-f]+", parts[2]):
    return False
  method_parts = parts[0].split(":")
  if method_parts[0] == "pbkdf2":
    return (
        len(method_parts) == 3
        and method_parts[1] == "sha256"
        and method_parts[2].isdigit()
    )
  if method_parts[0] == "scrypt":
    return len(method_parts) == 4 and all(part.isdigit() for part in method_parts[1:])
  return False


def verify_password(password_hash, password):
  try:
    return check_password_hash(password_hash, password)
  except (TypeError, ValueError) as error:
    app.logger.warning("Rejected malformed stored password hash: %s", error)
    return False


def hash_password(password):
  return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def csrf_token():
  token = session.get("_csrf_token")
  if token is None:
    token = secrets.token_urlsafe(32)
    session["_csrf_token"] = token
  return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_requests():
  if request.endpoint != "login" and not session.get("authenticated"):
    next_url = request.full_path if request.query_string else request.path
    return redirect(url_for("login", next=next_url))
  if request.endpoint != "login" and session.get("authenticated"):
    cur = get_db().cursor()
    cur.execute(
        "SELECT id, username, role FROM users WHERE id = %s AND active = TRUE",
        (session.get("user_id"),),
    )
    g.current_user = cur.fetchone()
    cur.close()
    if g.current_user is None:
      session.clear()
      return redirect(url_for("login"))
  if request.method == "POST":
    submitted_token = request.form.get("csrf_token", "")
    if not submitted_token or not hmac.compare_digest(submitted_token, csrf_token()):
      abort(400, description="Jeton CSRF invalide ou expiré.")


@app.route("/login", methods=["GET", "POST"])
def login():
  error = None
  if request.method == "POST":
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    cur = get_db().cursor()
    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username = %s AND active = TRUE",
        (username,),
    )
    user = cur.fetchone()
    cur.close()
    if user and verify_password(user["password_hash"], password):
      if not user["password_hash"].startswith(PASSWORD_HASH_METHOD + "$"):
        cur = get_db().cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (hash_password(password), user["id"]),
        )
        get_db().commit()
        cur.close()
      session.clear()
      session["authenticated"] = True
      session["user_id"] = user["id"]
      csrf_token()
      next_url = request.args.get("next", "")
      if next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
      return redirect(url_for("home"))
    error = "Identifiant ou mot de passe incorrect."
  return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=csrf_token())


@app.route("/logout", methods=["POST"])
def logout():
  session.clear()
  return redirect(url_for("login"))


def require_admin():
  current_user = getattr(g, "current_user", None)
  if not current_user or current_user["role"] != "admin":
    abort(403)


def get_db():
  if "db" not in g:
    g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
  return g.db


@app.teardown_appcontext
def close_connection(_exception):
  db = g.pop("db", None)
  if db is not None:
    db.close()


def init_db():
  if not DATABASE_URL:
    return
  conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
  conn.autocommit = True
  cursor = conn.cursor(row_factory=dict_row)
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS locations (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS equipment (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS articles (
            id SERIAL PRIMARY KEY,
            reference TEXT,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL DEFAULT 0.0,
            is_estimated_price INTEGER DEFAULT 0,
            min_threshold INTEGER DEFAULT 2,
            supplier TEXT,
            invoice_number TEXT,
            entry_date DATE,
            location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL,
            equipment_id INTEGER REFERENCES equipment(id) ON DELETE SET NULL,
            image_filename TEXT
        );
        CREATE TABLE IF NOT EXISTS movements (
            id SERIAL PRIMARY KEY,
            article_id INTEGER REFERENCES articles(id) ON DELETE SET NULL,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            supplier TEXT,
            invoice_number TEXT,
            reason TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
  cursor.execute("SELECT pg_advisory_lock(73401219078123::bigint)")
  try:
    cursor.execute("SELECT COUNT(*) AS count FROM users")
    if cursor.fetchone()["count"] == 0:
      if not APP_PASSWORD_HASH:
        raise RuntimeError(
            "La base ne contient aucun utilisateur. Définissez APP_PASSWORD_HASH "
            "pour initialiser le compte administrateur."
        )
      if not is_usable_password_hash(APP_PASSWORD_HASH):
        raise RuntimeError(
            "APP_PASSWORD_HASH est invalide. Générez-le avec Werkzeug en utilisant "
            "la méthode pbkdf2:sha256."
        )
      if not APP_USERNAME.strip():
        raise RuntimeError("APP_USERNAME ne peut pas être vide.")
      cursor.execute(
          """
              INSERT INTO users (username, password_hash, role)
              VALUES (%s, %s, 'admin')
              ON CONFLICT (username) DO NOTHING
          """,
          (APP_USERNAME.strip().lower(), APP_PASSWORD_HASH),
      )
    elif APP_PASSWORD_HASH and APP_USERNAME.strip():
      cursor.execute(
          "SELECT id, password_hash FROM users WHERE username = %s AND role = 'admin'",
          (APP_USERNAME.strip().lower(),),
      )
      admin_user = cursor.fetchone()
      if (
          admin_user
          and not is_usable_password_hash(admin_user["password_hash"])
          and is_usable_password_hash(APP_PASSWORD_HASH)
      ):
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (APP_PASSWORD_HASH, admin_user["id"]),
        )
        app.logger.warning(
            "Replaced malformed password hash for the configured administrator."
        )
  finally:
    cursor.execute("SELECT pg_advisory_unlock(73401219078123::bigint)")
  cursor.execute("""
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS min_threshold INTEGER DEFAULT 2;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS invoice_number TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS entry_date DATE;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS invoice_number TEXT;
    """)
  cursor.execute("SELECT pg_advisory_lock(73401219078123::bigint)")
  try:
    cursor.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'movements_article_id_fkey'
                  AND conrelid = 'movements'::regclass
                  AND confdeltype <> 'n'
            ) THEN
                ALTER TABLE movements DROP CONSTRAINT movements_article_id_fkey;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'movements_article_id_fkey'
                  AND conrelid = 'movements'::regclass
            ) THEN
                ALTER TABLE movements ADD CONSTRAINT movements_article_id_fkey
                    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE SET NULL;
            END IF;
        END;
        $$;
    """)
  finally:
    cursor.execute("SELECT pg_advisory_unlock(73401219078123::bigint)")
  cursor.close()
  conn.close()


with app.app_context():
  init_db()


# --- LAYOUT UNIFIÉ & CHARTE GRAPHIQUE (Vert Sapin Naturel) ---

LAYOUT_HEADER = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b3d2c">
    <title>Gestion & Suivi de Stock</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; font-size: 11px; }
            .print-table { border: 1px solid #CBD5E1 !important; }
            .print-table { min-width: 0 !important; }
            .page-break { page-break-before: always; }
        }
        .bg-forest { background-color: #0b3d2c; }
        .bg-forest-light { background-color: #124e38; }
        .border-forest { border-color: #0b3d2c; }
        .text-forest { color: #0b3d2c; }
        html { -webkit-text-size-adjust: 100%; scroll-behavior: smooth; }
        body { overflow-x: hidden; }
        input, select, textarea, button { max-width: 100%; }
        button, a, input[type="checkbox"], input[type="file"] { touch-action: manipulation; }
        input[type="checkbox"] { width: 1.25rem; height: 1.25rem; }
        .print-table { min-width: 980px; }
        .overflow-x-auto { -webkit-overflow-scrolling: touch; }
        @media (max-width: 767px) {
            input:not([type="checkbox"]):not([type="file"]), select, textarea {
                font-size: 16px !important;
            }
            button, input[type="submit"], select { min-height: 44px; }
            .print-table { min-width: 920px; }
        }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 font-sans antialiased min-h-screen flex flex-col">

    <!-- Header / Navbar Principal -->
    <header class="bg-forest text-white shadow-md border-b border-emerald-900 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex flex-col gap-3 py-3 md:flex-row md:items-center md:justify-between md:h-16 md:py-0">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-forest-light rounded-lg flex items-center justify-center font-bold text-emerald-300 border border-emerald-700 shadow-inner">
                        🌿
                    </div>
                    <div>
                        <a href="/" class="text-sm font-extrabold tracking-wider uppercase text-white block">SUIVI INVENTAIRE</a>
                        <span class="text-[10px] text-emerald-300 font-medium tracking-wide">CAPITAL IMMOBILISÉ : {{ "%.2f"|format(total_stock_value or 0) }} €</span>
                    </div>
                </div>

                <nav class="grid grid-cols-2 gap-1 sm:flex sm:flex-wrap sm:items-center sm:justify-end sm:gap-1">
                    <span class="col-span-2 text-center px-2 py-1 text-[10px] text-emerald-200 sm:col-span-1">{{ g.current_user.username }}</span>
                    <a href="/entry" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'entry' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>✏️</span> Saisie
                    </a>
                    <a href="/stock" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'stock' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>📊</span> Suivi & Rapport
                    </a>
                    <a href="/settings" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'settings' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>⚙️</span> Réglages
                    </a>
                    <form action="{{ url_for('logout') }}" method="POST" class="col-span-2 sm:col-span-1">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <button class="w-full min-h-11 px-3 py-2 rounded-md text-xs font-semibold text-emerald-100 hover:bg-forest-light">Déconnexion</button>
                    </form>
                </nav>
            </div>
        </div>
    </header>

    <main class="flex-grow max-w-7xl w-full min-w-0 mx-auto p-3 sm:p-6 lg:p-8">
"""

LAYOUT_FOOTER = """
    </main>
    <footer class="bg-forest text-emerald-300/70 text-[11px] py-4 border-t border-emerald-900 text-center no-print mt-auto">
        Système de Gestion de Stock & Operations | Facility Management
    </footer>
</body>
</html>
"""

# --- 1. PAGE DE SAISIE DE DONNÉES ---
ENTRY_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-3xl mx-auto space-y-6">
        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-4 flex justify-between items-center">
            <div>
                <h1 class="text-base font-bold text-slate-900">Saisie des Mouvements</h1>
                <p class="text-xs text-slate-500">Enregistrez de nouvelles entrées ou consommez du matériel pour intervention</p>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="bg-forest px-6 py-3 border-b border-emerald-900 flex gap-4">
                <span class="text-xs font-bold text-white uppercase tracking-wider">Formulaire d'enregistrement</span>
            </div>
            
            <div class="p-4 sm:p-6 space-y-6">
                <!-- Section Entrée -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-600"></span> Entrée en stock / Nouvel Article
                    </h2>
                    
                    <form action="/add" method="POST" enctype="multipart/form-data" class="space-y-4">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div class="md:col-span-2">
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Nom de l'article *</label>
                                <input type="text" name="name" required placeholder="ex: Disjoncteur 16A" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                                <input type="text" name="reference" placeholder="ex: REF-8840" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité initiale *</label>
                                <input type="number" name="quantity" value="1" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Stock Mini (Alerte) *</label>
                                <input type="number" name="min_threshold" value="2" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold text-rose-600">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Prix unitaire (€)</label>
                                <input type="number" step="0.01" name="price" value="0.00" required class="w-full text-xs p-2.5 border border-slate-300 rounded">
                            </div>
                            <div class="flex items-end pb-2">
                                <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
                                    <input type="checkbox" name="is_estimated_price" value="1" class="rounded border-slate-300 text-emerald-800">
                                    <span>Prix estimé</span>
                                </label>
                            </div>
                        </div>

                        <!-- Champs Fournisseur, Facture & Date d'entrée -->
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Fournisseur</label>
                                <input type="text" name="supplier" placeholder="ex: Rexel, Leroy Merlin..." class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">N° de facture</label>
                                <input type="text" name="invoice_number" placeholder="ex: FAC-2026-99" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Date d'entrée</label>
                                <input type="date" name="entry_date" value="{{ today_date }}" required class="w-full text-xs p-2 border border-slate-300 rounded bg-white font-medium">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Emplacement du stock</label>
                                <select name="location_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                    <option value="">-- Sélectionner un lieu --</option>
                                    {% for loc in locations %}
                                    <option value="{{ loc.id }}">{{ loc.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Équipement associé</label>
                                <select name="equipment_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                    <option value="">-- Sélectionner une machine --</option>
                                    {% for eq in equipment %}
                                    <option value="{{ eq.id }}">{{ eq.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                        </div>

                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Photo de l'article</label>
                            <input type="file" name="photo" accept="image/*" class="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-emerald-50 file:text-emerald-900">
                        </div>

                        <button type="submit" class="w-full bg-forest hover:bg-forest-light text-white font-semibold py-2.5 rounded text-xs transition shadow-sm">
                            Valider l'Entrée
                        </button>
                    </form>
                </div>

                <hr class="border-slate-200 my-6">

                <!-- Section Sortie -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-amber-500"></span> Sortie de stock / Consommation (Date enregistrée automatiquement)
                    </h2>

                    <form action="/movement_exit" method="POST" class="space-y-4">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Article à prélever *</label>
                            <select name="article_id" required class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                <option value="">-- Choisir une pièce --</option>
                                {% for item in articles %}
                                <option value="{{ item.id }}">{{ item.name }} (Réf: {{ item.reference or 'N/C' }}) | Qte dispo: {{ item.quantity }}</option>
                                {% endfor %}
                            </select>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité sortie *</label>
                                <input type="number" name="qty" value="1" min="1" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Motif / Intervenant *</label>
                                <input type="text" name="reason" required placeholder="ex: Dépannage pompe" class="w-full text-xs p-2.5 border border-slate-300 rounded">
                            </div>
                        </div>

                        <button type="submit" class="w-full bg-slate-700 hover:bg-slate-800 text-white font-semibold py-2.5 rounded text-xs transition shadow-sm">
                            Enregistrer la Sortie (Date automatique)
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 2. PAGE DE SUIVI DES DONNÉES ET INVENTAIRE PAR LIEU (Corrigé avec group['items']) ---
STOCK_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="space-y-6">
        <div class="bg-forest text-white rounded-lg p-4 sm:p-5 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border border-emerald-900">
            <div>
                <span class="text-[11px] font-semibold uppercase tracking-wider text-emerald-200">Valeur totale de l'inventaire</span>
                <div class="text-2xl font-extrabold text-white mt-0.5">{{ "%.2f"|format(total_stock_value) }} €</div>
            </div>
            <div class="flex gap-2 no-print">
                <button onclick="window.print()" class="bg-forest-light hover:bg-emerald-900 text-xs font-semibold px-4 py-2 rounded border border-emerald-700 text-white transition">
                    🖨️ Imprimer / PDF
                </button>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm no-print">
            <form method="GET" action="/stock" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input type="text" name="search" value="{{ search_query or '' }}" placeholder="Rechercher désignation..." class="text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                <select name="loc_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les emplacements</option>
                    {% for loc in locations %}
                    <option value="{{ loc.id }}" {% if current_loc == loc.id|string %}selected{% endif %}>{{ loc.name }}</option>
                    {% endfor %}
                </select>
                <select name="eq_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les équipements</option>
                    {% for eq in equipment %}
                    <option value="{{ eq.id }}" {% if current_eq == eq.id|string %}selected{% endif %}>{{ eq.name }}</option>
                    {% endfor %}
                </select>
                <div class="flex gap-2">
                    <button type="submit" class="flex-1 bg-forest text-white text-xs font-semibold py-2 rounded hover:bg-forest-light transition">Filtrer</button>
                    {% if search_query or current_loc or current_eq %}
                    <a href="/stock" class="px-3 py-2 text-xs bg-slate-100 text-slate-600 rounded hover:bg-slate-200 flex items-center">Effacer</a>
                    {% endif %}
                </div>
            </form>
        </div>

        <!-- RESTRUCTURATION : INVENTAIRE GROUPÉ PAR LIEU DE STOCKAGE -->
        {% if grouped_articles %}
            {% for group in grouped_articles %}
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden mb-6">
                <!-- En-tête du Lieu -->
                <div class="bg-forest text-white px-4 py-3 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 border-b border-emerald-900">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="text-base text-emerald-300">📍</span>
                        <h2 class="text-sm font-bold tracking-wide uppercase">{{ group.location_name }}</h2>
                        <span class="text-[11px] bg-forest-light text-emerald-200 px-2 py-0.5 rounded-full font-semibold border border-emerald-800">
                            {{ group['items'] | length }} article(s)
                        </span>
                    </div>
                    <div class="text-xs font-semibold text-emerald-300">
                        Valeur Lieu : {{ "%.2f"|format(group.total_value) }} €
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-xs print-table">
                        <thead>
                            <tr class="bg-emerald-50/60 text-slate-700 border-b border-slate-200 uppercase font-semibold text-[10px] tracking-wider">
                                <th class="p-2.5 border-r border-slate-200">Statut</th>
                                <th class="p-2.5 border-r border-slate-200">N° Article</th>
                                <th class="p-2.5 border-r border-slate-200">Désignation</th>
                                <th class="p-2.5 border-r border-slate-200">Fournisseur / Facture</th>
                                <th class="p-2.5 border-r border-slate-200">Équipement</th>
                                <th class="p-2.5 border-r border-slate-200 text-right">Prix Unit.</th>
                                <th class="p-2.5 border-r border-slate-200 text-center">Stock Mini</th>
                                <th class="p-2.5 border-r border-slate-200 text-center">Quantité</th>
                                <th class="p-2.5 text-right border-r border-slate-200">Valeur Totale</th>
                                <th class="p-2.5 text-center no-print">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-200">
                            {% for item in group['items'] %}
                            <tr class="{% if item.quantity < item.min_threshold %}bg-rose-50/80 hover:bg-rose-100/80{% else %}hover:bg-slate-50/60{% endif %} transition">
                                <td class="p-2.5 font-bold border-r border-slate-200">
                                    {% if item.quantity < item.min_threshold %}
                                    <span class="px-2 py-0.5 rounded text-[9px] bg-rose-200 text-rose-900 font-bold uppercase">RECOMMANDER</span>
                                    {% else %}
                                    <span class="px-2 py-0.5 rounded text-[9px] bg-emerald-100 text-emerald-900 font-semibold uppercase">OK</span>
                                    {% endif %}
                                </td>
                                <td class="p-2.5 font-mono text-slate-500 border-r border-slate-200">{{ item.reference or '-' }}</td>
                                <td class="p-2.5 font-semibold text-slate-900 border-r border-slate-200">
                                    {{ item.name }}
                                    {% if item.is_estimated_price %}
                                    <span class="text-[9px] text-amber-700 bg-amber-50 px-1 rounded ml-1 font-normal">(Est.)</span>
                                    {% endif %}
                                </td>
                                <td class="p-2.5 text-slate-600 border-r border-slate-200">
                                    <div class="font-medium text-slate-900">{{ item.supplier or '-' }}</div>
                                    <div class="text-[9px] text-slate-400">Fac: {{ item.invoice_number or '-' }} (Entrée: {{ item.entry_date or '-' }})</div>
                                </td>
                                <td class="p-2.5 text-slate-600 border-r border-slate-200">{{ item.eq_name or '-' }}</td>
                                <td class="p-2.5 text-right text-slate-700 border-r border-slate-200 font-mono">{{ "%.2f"|format(item.price) }} €</td>
                                <td class="p-2.5 text-center font-bold text-slate-600 border-r border-slate-200 bg-slate-50/50">{{ item.min_threshold }}</td>
                                <td class="p-2.5 text-center font-extrabold text-slate-900 border-r border-slate-200">{{ item.quantity }}</td>
                                <td class="p-2.5 text-right font-bold text-slate-900 font-mono border-r border-slate-200">{{ "%.2f"|format(item.quantity * item.price) }} €</td>
                                <td class="p-2.5 text-center no-print">
                                    <div class="flex items-center justify-center gap-1.5">
                                        <a href="/edit/{{ item.id }}" class="text-emerald-800 hover:underline font-semibold text-xs">✏️ Modif</a>
                                        <form action="/update/{{ item.id }}" method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <input type="hidden" name="action" value="minus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">-</button>
                                        </form>
                                        <form action="/update/{{ item.id }}" method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <input type="hidden" name="action" value="plus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">+</button>
                                        </form>
                                        <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('Supprimer cet article ?');" class="inline ml-1">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <button type="submit" class="text-rose-600 hover:underline text-xs">Suppr</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="bg-white rounded-lg border border-slate-200 p-8 text-center text-slate-400 text-xs shadow-sm">
                Aucun article ne correspond à votre recherche ou l'inventaire est vide.
            </div>
        {% endif %}
    </div>
"""
    + LAYOUT_FOOTER
)

# --- EDIT ARTICLE TEMPLATE ---
EDIT_ARTICLE_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-2xl mx-auto space-y-6">
        <div class="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-4">
            <div class="flex justify-between items-center pb-3 border-b border-slate-200">
                <h1 class="text-base font-bold text-slate-900">✏️ Modifier l'Article</h1>
                <a href="/stock" class="text-xs text-emerald-800 hover:underline font-semibold">← Retour au tableau</a>
            </div>

            <form action="/edit/{{ article.id }}" method="POST" enctype="multipart/form-data" class="space-y-4">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="md:col-span-2">
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Désignation / Nom *</label>
                        <input type="text" name="name" value="{{ article.name }}" required class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                        <input type="text" name="reference" value="{{ article.reference or '' }}" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité *</label>
                        <input type="number" name="quantity" value="{{ article.quantity }}" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Stock Mini *</label>
                        <input type="number" name="min_threshold" value="{{ article.min_threshold }}" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold text-rose-600">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Prix Unitaire (€)</label>
                        <input type="number" step="0.01" name="price" value="{{ article.price }}" required class="w-full text-xs p-2.5 border border-slate-300 rounded">
                    </div>
                    <div class="flex items-end pb-2">
                        <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
                            <input type="checkbox" name="is_estimated_price" value="1" {% if article.is_estimated_price %}checked{% endif %} class="rounded border-slate-300 text-emerald-800">
                            <span>Prix estimé</span>
                        </label>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Fournisseur</label>
                        <input type="text" name="supplier" value="{{ article.supplier or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">N° de facture</label>
                        <input type="text" name="invoice_number" value="{{ article.invoice_number or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Date d'entrée</label>
                        <input type="date" name="entry_date" value="{{ article.entry_date or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white font-medium">
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Emplacement</label>
                        <select name="location_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                            <option value="">-- Aucun --</option>
                            {% for loc in locations %}
                            <option value="{{ loc.id }}" {% if article.location_id == loc.id %}selected{% endif %}>{{ loc.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Équipement</label>
                        <select name="equipment_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                            <option value="">-- Aucun --</option>
                            {% for eq in equipment %}
                            <option value="{{ eq.id }}" {% if article.equipment_id == eq.id %}selected{% endif %}>{{ eq.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-600 mb-1">Remplacer la photo (Optionnel)</label>
                    <input type="file" name="photo" accept="image/*" class="w-full text-xs text-slate-500">
                </div>

                <div class="flex gap-3 pt-2">
                    <button type="submit" class="flex-1 bg-forest hover:bg-forest-light text-white font-semibold py-2.5 rounded text-xs transition">Mettre à jour l'article</button>
                    <a href="/stock" class="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded text-center">Annuler</a>
                </div>
            </form>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 3. PAGE DE RÉGLAGES ---
SETTINGS_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-white rounded-lg border border-slate-200 p-4 shadow-sm">
            <h1 class="text-base font-bold text-slate-900">Réglages & Configuration</h1>
            <p class="text-xs text-slate-500">Gérez et modifiez les emplacements physiques et les équipements associés</p>
        </div>
        {% for category, message in get_flashed_messages(with_categories=true) %}
        <p role="status" class="rounded p-3 text-sm {% if category == 'error' %}bg-rose-50 text-rose-800{% else %}bg-emerald-50 text-emerald-800{% endif %}">{{ message }}</p>
        {% endfor %}

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Emplacements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    📍 Emplacements de Stockage
                </h2>
                <form action="/add_location" method="POST" class="flex gap-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="text" name="name" required placeholder="Nouveau lieu..." class="flex-grow text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <button type="submit" class="bg-forest hover:bg-forest-light text-white px-3 py-2 rounded text-xs font-semibold transition">Ajouter</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for loc in locations %}
                    <div class="py-2.5 flex justify-between items-center">
                        <form action="/edit_location/{{ loc.id }}" method="POST" class="flex items-center gap-2 flex-grow mr-2">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <input type="text" name="name" value="{{ loc.name }}" required class="text-xs p-1 border border-transparent hover:border-slate-300 focus:border-emerald-700 rounded flex-grow font-semibold text-slate-700">
                            <button type="submit" class="text-emerald-800 hover:underline text-[11px] font-medium">Sauvegarder</button>
                        </form>
                        <form action="/delete_location/{{ loc.id }}" method="POST" onsubmit="return confirm('Supprimer ce lieu ?');">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                        </form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun lieu configuré.</p>
                    {% endfor %}
                </div>
            </div>

            <!-- Équipements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    ⚙️ Équipements & Machines
                </h2>
                <form action="/add_equipment" method="POST" class="space-y-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="text" name="name" required placeholder="Nom de l'équipement..." class="w-full text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <select name="location_id" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                        <option value="">-- Rattacher à un emplacement --</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">{{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-forest hover:bg-forest-light text-white py-2 rounded text-xs font-semibold transition">Ajouter l'Équipement</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for eq in equipment %}
                    <div class="py-3 space-y-1">
                        <form action="/edit_equipment/{{ eq.id }}" method="POST" class="space-y-1.5">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <div class="flex gap-2">
                                <input type="text" name="name" value="{{ eq.name }}" required class="text-xs p-1 border border-slate-200 rounded flex-grow font-semibold text-slate-800 focus:border-emerald-700">
                                <button type="submit" class="text-emerald-800 hover:underline text-[11px] font-medium">Sauvegarder</button>
                            </div>
                            <div class="flex justify-between items-center">
                                <select name="location_id" class="text-[11px] p-1 border border-slate-200 rounded bg-white text-slate-600">
                                    <option value="">-- Aucun lieu --</option>
                                    {% for loc in locations %}
                                    <option value="{{ loc.id }}" {% if eq.location_id == loc.id %}selected{% endif %}>📍 {{ loc.name }}</option>
                                    {% endfor %}
                                </select>
                                <button type="submit" form="del_eq_{{ eq.id }}" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                            </div>
                        </form>
                        <form id="del_eq_{{ eq.id }}" action="/delete_equipment/{{ eq.id }}" method="POST" onsubmit="return confirm('Supprimer cet équipement ?');"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"></form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun équipement configuré.</p>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% if current_user.role == 'admin' %}
        <section class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
            <div>
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider">Gestion des utilisateurs</h2>
                <p class="text-xs text-slate-500 mt-1">Les nouveaux comptes n'ont pas accès à la gestion des utilisateurs.</p>
            </div>
            <form action="{{ url_for('add_user') }}" method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input name="username" required minlength="3" maxlength="64" autocomplete="username" placeholder="Identifiant ou e-mail" title="3 à 64 caractères ; lettres, chiffres, point, tiret, souligné, @ ou +" class="text-xs p-2 border border-slate-300 rounded">
                <input type="password" name="password" required minlength="12" autocomplete="new-password" placeholder="Mot de passe (12 caractères min.)" class="text-xs p-2 border border-slate-300 rounded">
                <select name="role" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="user">Utilisateur</option>
                    <option value="admin">Administrateur</option>
                </select>
                <button type="submit" class="bg-forest hover:bg-forest-light text-white rounded text-xs font-semibold">Créer le compte</button>
            </form>
            <div class="divide-y divide-slate-100">
                {% for account in users %}
                <div class="py-3 flex flex-col gap-3">
                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <span class="font-semibold text-slate-800">{{ account.username }}</span>
                        <span class="text-slate-500">{{ 'Administrateur' if account.role == 'admin' else 'Utilisateur' }} · {{ 'Actif' if account.active else 'Désactivé' }}</span>
                        {% if account.id != current_user.id %}
                        <form action="{{ url_for('toggle_user', user_id=account.id) }}" method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="text-xs font-medium {% if account.active %}text-rose-700{% else %}text-emerald-800{% endif %}">{{ 'Désactiver' if account.active else 'Réactiver' }}</button>
                        </form>
                        {% else %}
                        <span class="text-slate-400">Votre compte</span>
                        {% endif %}
                    </div>
                    <form action="{{ url_for('reset_user_password', user_id=account.id) }}" method="POST" class="flex flex-wrap gap-2">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="password" name="password" required minlength="12" autocomplete="new-password" placeholder="Nouveau mot de passe (12 caractères min.)" class="flex-grow text-xs p-2 border border-slate-300 rounded">
                        <button type="submit" class="text-xs px-3 py-2 rounded bg-slate-100 hover:bg-slate-200">Réinitialiser le mot de passe</button>
                    </form>
                </div>
                {% else %}
                <p class="text-slate-400 text-xs italic py-3">Aucun utilisateur.</p>
                {% endfor %}
            </div>
        </section>
        {% endif %}
    </div>
"""
    + LAYOUT_FOOTER
)


# --- ROUTES FLASK ---


def calculate_total_stock_value(articles_list=None):
  db = get_db()
  cur = db.cursor()
  if articles_list is None:
    cur.execute("SELECT quantity, price FROM articles")
    articles_list = cur.fetchall()
  cur.close()
  return sum(
      (item["quantity"] * (item["price"] or 0.0)) for item in articles_list
  )


@app.route("/")
def home():
  return redirect(url_for("stock_view"))


@app.route("/entry")
def entry_form():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()
  cur.execute(
      "SELECT a.*, l.name as loc_name FROM articles a LEFT JOIN locations l ON"
      " a.location_id = l.id ORDER BY a.name"
  )
  articles = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  today_str = datetime.date.today().strftime("%Y-%m-%d")
  return render_template_string(
      ENTRY_TEMPLATE,
      active_page="entry",
      locations=locations,
      equipment=equipment,
      articles=articles,
      total_stock_value=total_val,
      today_date=today_str,
  )


@app.route("/stock")
def stock_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()

  search_query = request.args.get("search", "").strip()
  loc_filter = optional_integer(request.args.get("loc_filter"), "loc_filter")
  eq_filter = optional_integer(request.args.get("eq_filter"), "eq_filter")

  query = """
        SELECT a.*, COALESCE(l.name, 'Non assigné') as loc_name, e.name as eq_name 
        FROM articles a
        LEFT JOIN locations l ON a.location_id = l.id
        LEFT JOIN equipment e ON a.equipment_id = e.id
        WHERE 1=1
    """
  params = []

  if search_query:
    query += " AND (a.name ILIKE %s OR a.reference ILIKE %s)"
    params.extend([f"%{search_query}%", f"%{search_query}%"])
  if loc_filter:
    query += " AND a.location_id = %s"
    params.append(loc_filter)
  if eq_filter:
    query += " AND a.equipment_id = %s"
    params.append(eq_filter)

  query += " ORDER BY loc_name ASC, a.name ASC"
  cur.execute(query, params)
  articles = cur.fetchall()
  cur.close()

  total_stock_value = calculate_total_stock_value()

  # Groupement dynamique strict par lieu de stockage sous forme de listes de dictionnaires
  grouped_dict = {}
  for item in articles:
    loc_name = item["loc_name"]
    if loc_name not in grouped_dict:
      grouped_dict[loc_name] = {"items": [], "total_value": 0.0}
    grouped_dict[loc_name]["items"].append(item)
    grouped_dict[loc_name]["total_value"] += item["quantity"] * (
        item["price"] or 0.0
    )

  grouped_articles = [
      {
          "location_name": loc_name,
          "items": list(data["items"]),
          "total_value": data["total_value"],
      }
      for loc_name, data in grouped_dict.items()
  ]

  return render_template_string(
      STOCK_TEMPLATE,
      active_page="stock",
      locations=locations,
      equipment=equipment,
      grouped_articles=grouped_articles,
      search_query=search_query,
      current_loc=loc_filter,
      current_eq=eq_filter,
      total_stock_value=total_stock_value,
  )


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_article(id):
  db = get_db()
  cur = db.cursor()

  if request.method == "POST":
    name = request.form.get("name", "").strip()
    if not name:
      abort(400, description="Le nom de l'article est obligatoire.")
    reference = request.form.get("reference")
    quantity = form_integer("quantity", minimum=0)
    min_threshold = form_integer("min_threshold", default=2, minimum=0)
    price = form_price()
    is_estimated_price = 1 if "is_estimated_price" in request.form else 0
    supplier = request.form.get("supplier")
    invoice_number = request.form.get("invoice_number")
    entry_date = request.form.get("entry_date") or None
    if entry_date:
      try:
        entry_date = datetime.date.fromisoformat(entry_date)
      except ValueError:
        abort(400, description="La date d'entrée est invalide.")
    location_id = optional_integer(request.form.get("location_id"), "location_id")
    equipment_id = optional_integer(request.form.get("equipment_id"), "equipment_id")

    cur.execute("SELECT quantity FROM articles WHERE id = %s FOR UPDATE", (id,))
    article = cur.fetchone()
    if article is None:
      abort(404)
    old_quantity = article["quantity"]
    filename = save_uploaded_image(request.files.get("photo"))
    if filename:
      cur.execute(
          """
              UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s,
              is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s,
              equipment_id=%s, image_filename=%s WHERE id=%s
          """,
          (
              name, reference, quantity, min_threshold, price, is_estimated_price,
              supplier, invoice_number, entry_date, location_id, equipment_id, filename, id,
          ),
      )
    else:
      cur.execute(
          """
              UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s,
              is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s,
              equipment_id=%s WHERE id=%s
          """,
          (
              name, reference, quantity, min_threshold, price, is_estimated_price,
              supplier, invoice_number, entry_date, location_id, equipment_id, id,
          ),
      )
    quantity_delta = quantity - old_quantity
    if quantity_delta:
      cur.execute(
          """
              INSERT INTO movements (article_id, type, quantity, reason, date)
              VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
          """,
          (
              id,
              "ENTREE" if quantity_delta > 0 else "SORTIE",
              abs(quantity_delta),
              "Correction de stock via modification de l'article",
          ),
      )

    db.commit()
    cur.close()
    return redirect(url_for("stock_view"))

  cur.execute("SELECT * FROM articles WHERE id = %s", (id,))
  article = cur.fetchone()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()

  return render_template_string(
      EDIT_ARTICLE_TEMPLATE,
      active_page="stock",
      article=article,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
  )


@app.route("/settings")
def settings_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("""
        SELECT e.*, l.name as loc_name 
        FROM equipment e 
        LEFT JOIN locations l ON e.location_id = l.id 
        ORDER BY e.name
    """)
  equipment = cur.fetchall()
  cur.execute(
      "SELECT id, username, role, active FROM users ORDER BY username"
  )
  users = cur.fetchall() if g.current_user["role"] == "admin" else []
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      SETTINGS_TEMPLATE,
      active_page="settings",
      locations=locations,
      equipment=equipment,
      users=users,
      current_user=g.current_user,
      total_stock_value=total_val,
  )


@app.route("/users/add", methods=["POST"])
def add_user():
  require_admin()
  username = request.form.get("username", "").strip().lower()
  password = request.form.get("password", "")
  role = request.form.get("role", "user")
  if not re.fullmatch(r"[\w.@+-]{3,64}", username):
    abort(
        400,
        description=(
            "Identifiant invalide : utilisez 3 à 64 caractères sans espace "
            "(lettres, chiffres, point, tiret, souligné, @ ou +)."
        ),
    )
  if len(password) < 12:
    abort(400, description="Le mot de passe doit contenir au moins 12 caractères.")
  if role not in {"user", "admin"}:
    abort(400, description="Rôle utilisateur invalide.")

  cur = get_db().cursor()
  cur.execute(
      """
          INSERT INTO users (username, password_hash, role)
          VALUES (%s, %s, %s)
          ON CONFLICT (username) DO NOTHING
          RETURNING id
      """,
      (username, hash_password(password), role),
  )
  if cur.fetchone() is None:
    cur.close()
    flash("Cet identifiant existe déjà.", "error")
    return redirect(url_for("settings_view"))
  get_db().commit()
  cur.close()
  flash(f"Le compte « {username} » a été créé.", "success")
  return redirect(url_for("settings_view"))


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
def toggle_user(user_id):
  require_admin()
  if user_id == g.current_user["id"]:
    abort(400, description="Vous ne pouvez pas désactiver votre propre compte.")

  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT pg_advisory_xact_lock(73401219078124::bigint)")
  cur.execute(
      "SELECT role, active FROM users WHERE id = %s FOR UPDATE",
      (user_id,),
  )
  account = cur.fetchone()
  if account is None:
    cur.close()
    abort(404)
  if account["role"] == "admin" and account["active"]:
    cur.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = TRUE")
    if cur.fetchone()["count"] <= 1:
      db.rollback()
      cur.close()
      abort(400, description="Impossible de désactiver le dernier administrateur actif.")
  cur.execute("UPDATE users SET active = NOT active WHERE id = %s", (user_id,))
  db.commit()
  cur.close()
  flash("Le statut du compte a été modifié.", "success")
  return redirect(url_for("settings_view"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
def reset_user_password(user_id):
  require_admin()
  password = request.form.get("password", "")
  if len(password) < 12:
    abort(400, description="Le mot de passe doit contenir au moins 12 caractères.")
  cur = get_db().cursor()
  cur.execute(
      "UPDATE users SET password_hash = %s WHERE id = %s RETURNING username",
      (hash_password(password), user_id),
  )
  account = cur.fetchone()
  if account is None:
    cur.close()
    abort(404)
  get_db().commit()
  cur.close()
  flash(f"Le mot de passe du compte « {account['username']} » a été réinitialisé.", "success")
  return redirect(url_for("settings_view"))


@app.route("/add_location", methods=["POST"])
def add_location():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom du lieu est obligatoire.")
  cur.execute("INSERT INTO locations (name) VALUES (%s)", (name,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/edit_location/<int:id>", methods=["POST"])
def edit_location(id):
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom du lieu est obligatoire.")
  cur.execute("UPDATE locations SET name = %s WHERE id = %s", (name, id))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/delete_location/<int:id>", methods=["POST"])
def delete_location(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM locations WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/add_equipment", methods=["POST"])
def add_equipment():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'équipement est obligatoire.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  cur.execute(
      "INSERT INTO equipment (name, location_id) VALUES (%s, %s)",
      (name, location_id),
  )
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/edit_equipment/<int:id>", methods=["POST"])
def edit_equipment(id):
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'équipement est obligatoire.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  cur.execute(
      "UPDATE equipment SET name = %s, location_id = %s WHERE id = %s",
      (name, location_id, id),
  )
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/delete_equipment/<int:id>", methods=["POST"])
def delete_equipment(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM equipment WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/add", methods=["POST"])
def add_article():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'article est obligatoire.")
  reference = request.form.get("reference")
  quantity = form_integer("quantity", default=1, minimum=0)
  min_threshold = form_integer("min_threshold", default=2, minimum=0)
  price = form_price()
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  supplier = request.form.get("supplier")
  invoice_number = request.form.get("invoice_number")
  entry_date = request.form.get("entry_date") or datetime.date.today()
  if isinstance(entry_date, str):
    try:
      entry_date = datetime.date.fromisoformat(entry_date)
    except ValueError:
      abort(400, description="La date d'entrée est invalide.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  equipment_id = optional_integer(request.form.get("equipment_id"), "equipment_id")
  reason = f"Entrée - Fournisseur: {supplier or 'N/C'} | Facture: {invoice_number or 'N/C'}"

  filename = save_uploaded_image(request.files.get("photo"))

  cur.execute(
      """
        INSERT INTO articles (name, reference, quantity, min_threshold, price, is_estimated_price, supplier, invoice_number, entry_date, location_id, equipment_id, image_filename) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """,
      (
          name,
          reference,
          quantity,
          min_threshold,
          price,
          is_estimated_price,
          supplier,
          invoice_number,
          entry_date,
          location_id,
          equipment_id,
          filename,
      ),
  )
  article_id = cur.fetchone()["id"]

  cur.execute(
      """
        INSERT INTO movements (article_id, type, quantity, supplier, invoice_number, reason, date) 
        VALUES (%s, 'ENTREE', %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """,
      (article_id, quantity, supplier, invoice_number, reason),
  )
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


@app.route("/movement_exit", methods=["POST"])
def movement_exit():
  db = get_db()
  cur = db.cursor()
  article_id = form_integer("article_id", minimum=1)
  qty = form_integer("qty", minimum=1)
  reason = request.form.get("reason", "").strip()
  if not reason:
    abort(400, description="Le motif de sortie est obligatoire.")

  cur.execute(
      """
          UPDATE articles SET quantity = quantity - %s
          WHERE id = %s AND quantity >= %s
          RETURNING id
      """,
      (qty, article_id, qty),
  )
  if cur.fetchone() is None:
    db.rollback()
    abort(400, description="Article inexistant ou stock insuffisant.")
  cur.execute(
      """
          INSERT INTO movements (article_id, type, quantity, reason, date)
          VALUES (%s, 'SORTIE', %s, %s, CURRENT_TIMESTAMP)
      """,
      (article_id, qty, reason),
  )
  db.commit()
  cur.close()

  return redirect(url_for("stock_view"))


@app.route("/update/<int:id>", methods=["POST"])
def update_quantity(id):
  db = get_db()
  cur = db.cursor()
  action = request.form.get("action")
  if action not in {"plus", "minus"}:
    abort(400, description="Action de mise à jour invalide.")
  cur.execute("SELECT quantity FROM articles WHERE id = %s FOR UPDATE", (id,))
  item = cur.fetchone()
  if item is None:
    abort(404)
  current_qty = item["quantity"]
  if action == "minus" and current_qty == 0:
    abort(400, description="Le stock est déjà à zéro.")
  delta = 1 if action == "plus" else -1
  cur.execute("UPDATE articles SET quantity = quantity + %s WHERE id = %s", (delta, id))
  cur.execute(
      """
          INSERT INTO movements (article_id, type, quantity, reason, date)
          VALUES (%s, %s, 1, %s, CURRENT_TIMESTAMP)
      """,
      (id, "ENTREE" if delta > 0 else "SORTIE", "Ajustement manuel du stock"),
  )
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


@app.route("/delete/<int:id>", methods=["POST"])
def delete_article(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM articles WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=10000, debug=False)
